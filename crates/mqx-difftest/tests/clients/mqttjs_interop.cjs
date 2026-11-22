'use strict';

// From this directory: npm ci --ignore-scripts && node mqttjs_interop.cjs HOST PUB_PORT SUB_PORT tcp|ws
const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const { on, once } = require('node:events');
const mqtt = require('mqtt');

const [host, pubPort, subPort, transport, ...extra] = process.argv.slice(2);
const validPort = (port) => /^\d+$/.test(port) && Number(port) >= 1 && Number(port) <= 65535;
assert.ok(host && validPort(pubPort) && validPort(subPort) &&
  ['tcp', 'ws'].includes(transport) && extra.length === 0,
'usage: node mqttjs_interop.cjs HOST PUB_PORT SUB_PORT tcp|ws');
const authority = host.includes(':') && !host.startsWith('[') ? `[${host}]` : host;
const scheme = transport === 'tcp' ? 'mqtt' : 'ws';
const pubUrl = `${scheme}://${authority}:${pubPort}`;
const subUrl = `${scheme}://${authority}:${subPort}`;
const root = `mqx-interop/mqttjs/${randomUUID()}`;
const clients = [];
let phase = 'starting';
let closing = false;

function fail(error) {
  console.error(`MQTT.js ${transport} (${phase}):`, error);
  process.exit(1);
}

async function connect(url, protocolVersion) {
  const client = mqtt.connect(url, { protocolVersion, reconnectPeriod: 0 });
  clients.push(client);
  client.on('error', fail);
  client.on('close', () => {
    if (!closing) fail(new Error(`unexpected close at ${url} (protocol ${protocolVersion})`));
  });
  await once(client, 'connect');
  return client;
}

async function receive(messages, expectedTopic, expectedPayload, qos, retain = false) {
  const { value: [topic, payload, packet] } = await messages.next();
  assert.equal(topic, expectedTopic, 'first queued message topic');
  assert.deepEqual(payload, expectedPayload, `payload on ${topic}`);
  assert.equal(packet.qos, qos, `delivery QoS on ${topic}`);
  assert.equal(packet.retain, retain, `RETAIN on ${topic}`);
  return packet;
}

async function mqtt5() {
  phase = 'MQTT 5 CONNECT';
  const [pub, sub] = await Promise.all([connect(pubUrl, 5), connect(subUrl, 5)]);
  const pubMessages = on(pub, 'message');
  const subMessages = on(sub, 'message');
  let deliveries = 0;
  sub.on('message', () => { deliveries += 1; });

  const requestFilter = `${root}/requests/+`;
  const request = `${root}/requests/lookup`;
  const response = `${root}/responses/lookup`;
  const status = `${root}/status`;
  const subscriptionIdentifier = 704;
  phase = 'MQTT 5 SUBACK';
  const grants = await sub.subscribeAsync({
    [requestFilter]: { qos: 1, nl: true },
    [status]: { qos: 0, rap: true },
  }, { properties: { subscriptionIdentifier } });
  assert.deepEqual(grants.map(({ topic, qos }) => [topic, qos]), [[requestFilter, 1], [status, 0]]);
  assert.equal((await pub.subscribeAsync(response, { qos: 1 }))[0]?.qos, 1);

  // A second local publication must arrive, but the earlier No Local one must not.
  // MQTT 5 §3.8.3.1, Mosquitto src/subs.c: subs__process and subs__send.
  phase = 'MQTT 5 No Local and Retain As Published';
  await sub.publishAsync(request, 'must not loop back', { qos: 1 });
  const online = Buffer.from('online');
  await sub.publishAsync(status, online, { qos: 1, retain: true });
  const statusPacket = await receive(subMessages, status, online, 0, true);
  assert.equal(statusPacket.properties?.subscriptionIdentifier, subscriptionIdentifier);

  // MQTT 5 §3.3.2.3 and §4.10; Mosquitto src/property_broker.c: property__process_publish.
  phase = 'MQTT 5 request/response properties';
  const correlationData = Buffer.from([0x00, 0x01, 0x80, 0xff]);
  const userProperties = { trace: ['first', '두 번째'] };
  const query = Buffer.from('lookup');
  await pub.publishAsync(request, query, {
    qos: 1,
    properties: { responseTopic: response, correlationData, userProperties },
  });
  const requestPacket = await receive(subMessages, request, query, 1);
  const props = requestPacket.properties;
  assert.equal(props?.responseTopic, response);
  assert.deepEqual(props.correlationData, correlationData);
  assert.deepEqual(props.userProperties?.trace, userProperties.trace);
  assert.equal(props.subscriptionIdentifier, subscriptionIdentifier);

  const answer = Buffer.from([0xff, 0x00, 0x2a]);
  await sub.publishAsync(props.responseTopic, answer, {
    qos: 1,
    properties: { correlationData: props.correlationData },
  });
  const responsePacket = await receive(pubMessages, response, answer, 1);
  assert.deepEqual(responsePacket.properties?.correlationData, correlationData);

  phase = 'MQTT 5 batched UNSUBACK and retained cleanup';
  const unsuback = await sub.unsubscribeAsync([requestFilter, status]);
  assert.deepEqual(unsuback.granted, [0, 0]);
  await sub.publishAsync(status, Buffer.alloc(0), { qos: 1, retain: true });
  assert.equal(deliveries, 2, 'unexpected MQTT 5 delivery, including a possible No Local echo');
  await Promise.all([pubMessages.return(), subMessages.return()]);
}

async function mqtt311() {
  phase = 'MQTT 3.1.1 CONNECT';
  const [pub, sub] = await Promise.all([connect(pubUrl, 4), connect(subUrl, 4)]);
  const messages = on(sub, 'message');
  const topic = `${root}/legacy/qos2`;
  const payload = Buffer.from([0x00, 0x4d, 0xff]);
  // MQTT 3.1.1 §4.3.3: exercise the QoS 2 handshake in each direction.
  phase = 'MQTT 3.1.1 QoS 2';
  assert.equal((await sub.subscribeAsync(topic, { qos: 2 }))[0]?.qos, 2);
  await pub.publishAsync(topic, payload, { qos: 2 });
  await receive(messages, topic, payload, 2);
  await messages.return();
}

async function main() {
  await mqtt5();
  await mqtt311();
  phase = 'disconnecting';
  closing = true;
  await Promise.all(clients.map((client) => client.endAsync()));
}

const deadline = setTimeout(() => fail(new Error('20 s deadline exceeded')), 20_000);
main().then(() => {
  clearTimeout(deadline);
  console.log(`MQTT.js ${require('mqtt/package.json').version} ${transport}: MQTT 5 and 3.1.1 passed`);
}, fail);
