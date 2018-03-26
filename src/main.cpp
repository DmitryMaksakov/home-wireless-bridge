#include <Arduino.h>
#include <VirtualWire.h>
#include <EasyTransferVirtualWire.h>
#include <EEPROM.h>
#include <HashMap.h>
#include "sha1.h"

// Constants
const bool DEBUG_MODE = false;
const int LED_PIN = 13;
const int RECEIVE_PIN = 3;
const int RECEIVE_POWER_PIN = 4;
const unsigned char* SECRET = "QHcGpCh?mAzQ7vCW#4SZnZ5-2-r%2kfL";

// EasyTransfer object
EasyTransferVirtualWire ET;


// Last received packet number by sourceId counter
struct DEVICE_COUNTER {
  unsigned int sourceId;
  unsigned int packetNumber;
};

DEVICE_COUNTER* deviceCounters = 0;
unsigned int deviceCountersSize = 0;


// Packet structure
struct SEND_DATA_STRUCTURE {
  unsigned int sourceId; //4 bytes
  unsigned int packetNumber; //4 bytes
  byte commandType; // 1 byte
  float data; // 4 bytes
  byte hmac0; // 1 byte
  byte hmac2; // 1 byte
  byte hmac3; // 1 byte
  byte hmac4; // 1 byte
  byte hmac5; // 1 byte
  byte hmac6; // 1 byte
  byte hmac8; // 1 byte
  byte hmac11; // 1 byte
  byte hmac13; // 1 byte
  byte hmac15; // 1 byte
  byte hmac17; // 1 byte
  byte hmac18; // 1 byte
  byte hmac19; // 1 byte
};

// Current packet
SEND_DATA_STRUCTURE packet;

// If packet number is above last received, it is allowed packet. Otherwise packet will be dropped.
bool checkDeviceCounter(SEND_DATA_STRUCTURE packet) {
  for (unsigned int i = 0; i < deviceCountersSize; i++) {
    if (deviceCounters[i].sourceId == packet.sourceId) {
      if (packet.packetNumber > deviceCounters[i].packetNumber) {
        deviceCounters[i].packetNumber = packet.packetNumber;
        return true;
      } else {
        return false;
      }
    }
  }

  // Packet from new unknown device
  deviceCountersSize++;

  if (deviceCounters != 0) {
    deviceCounters = (DEVICE_COUNTER*) realloc(deviceCounters, deviceCountersSize * sizeof(DEVICE_COUNTER));
  } else {
    deviceCounters = (DEVICE_COUNTER*) malloc(deviceCountersSize * sizeof(DEVICE_COUNTER));
  }

  DEVICE_COUNTER newCounter;

  newCounter.sourceId = packet.sourceId;
  newCounter.packetNumber = packet.packetNumber;

  deviceCounters[deviceCountersSize - 1] = newCounter;

  return true;
}

// Blinks Arduino led with {ms} interval {count} times
void blink(int ms = 100, int count = 1)
{
  for(int i = 0; i < count; i++)
  {
    digitalWrite(LED_PIN, HIGH);
    delay(ms);
    digitalWrite(LED_PIN, LOW);
    delay(ms);
  }
}

// Initialization part
void setup()
{
  // Power on for receiver
  pinMode(RECEIVE_POWER_PIN, OUTPUT);
  digitalWrite(RECEIVE_POWER_PIN, HIGH);

  // Configuring led
  pinMode(LED_PIN, OUTPUT);

  // Starting serial
  Serial.begin(9600);

  // Init Easy Transfer lib
  ET.begin(details(packet));
  vw_set_rx_pin(RECEIVE_PIN);
  vw_setup(2000);
  vw_rx_start();

  // Indicate Device is ready
  blink(100, 3);
}

// Main loop
void loop()
{
  // On data received
  if (ET.receiveData())
  {
    // Calculating hash
    unsigned char *hash;

    Sha1.initHmac(SECRET, 32);
    Sha1.print(packet.sourceId);
    Sha1.print(packet.packetNumber);
    Sha1.print(packet.commandType);
    Sha1.print(packet.data);

    hash = Sha1.resultHmac();

    // If hash is ok
    if (
      hash[0] == packet.hmac0 &&
      hash[2] == packet.hmac2 &&
      hash[3] == packet.hmac3 &&
      hash[4] == packet.hmac4 &&
      hash[5] == packet.hmac5 &&
      hash[6] == packet.hmac6 &&
      hash[8] == packet.hmac8 &&
      hash[11] == packet.hmac11 &&
      hash[13] == packet.hmac13 &&
      hash[15] == packet.hmac15 &&
      hash[17] == packet.hmac17 &&
      hash[18] == packet.hmac18 &&
      hash[19] == packet.hmac19
    ) {
      // If packet is not outdated
      if (checkDeviceCounter(packet)) {
        digitalWrite(LED_PIN, HIGH);

        if (DEBUG_MODE) {
          Serial.println("Start");
          Serial.print("SourceId:");
          Serial.println(packet.sourceId);
          Serial.print("packetNumber:");
          Serial.println(packet.packetNumber);
          Serial.print("commandType:");
          Serial.println(packet.commandType);
          Serial.print("Data:");
          Serial.println(packet.data);
          Serial.println("End");
          Serial.println();
        }

        byte sourceIdLowByte = ((packet.sourceId >> 0) & 0xFF);
        byte sourceIdHighByte = ((packet.sourceId >> 8) & 0xFF);

        if (!DEBUG_MODE) {
          Serial.write(0);
          Serial.write(0);
          Serial.write(0);

          Serial.write(sourceIdLowByte);
          Serial.write(sourceIdHighByte);
          Serial.write(packet.commandType);

          Serial.print(packet.data);

          Serial.write(255);
          Serial.write(255);
          Serial.write(255);
        }

        digitalWrite(LED_PIN, LOW);
      } else {
        if (DEBUG_MODE) {
          Serial.println("Wrong packet Number:");
          Serial.println(packet.sourceId);
          Serial.println(packet.packetNumber);
          Serial.println();

          digitalWrite(LED_PIN, HIGH);
          delay(500);
          digitalWrite(LED_PIN, LOW);
        }
      }
    }
    else {
      if (DEBUG_MODE) {
        Serial.println("Wrong packet HMAC:");
        Serial.println(packet.sourceId);
        Serial.println(packet.packetNumber);
        Serial.println();

        digitalWrite(LED_PIN, HIGH);
        delay(500);
        digitalWrite(LED_PIN, LOW);
      }
    }
  }
}
