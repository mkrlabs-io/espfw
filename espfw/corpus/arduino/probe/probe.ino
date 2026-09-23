// A deliberately broad arduino-esp32 sketch, built only to make the linker emit
// code (§9.1).
//
// The linker emits only what is referenced, so a corpus built from a small
// sketch covers almost nothing: this is the difference between a few hundred
// signatures and several thousand. Every call below exists to pull a translation
// unit into the image, not to do anything sensible.
//
// Libraries are behind `__has_include` so one that failed to install, or that
// does not exist for this core version, costs its own coverage and nothing else.
// The core API surface is likewise version-guarded: 1.x, 2.x and 3.x differ, and
// a sketch that only compiles against one of them would silently narrow the
// corpus to that generation.

#include <Arduino.h>
#include <WiFi.h>
#include <WiFiClient.h>
#include <WiFiUdp.h>
#include <HTTPClient.h>
#include <WiFiClientSecure.h>
#include <WebServer.h>
#include <ESPmDNS.h>
#include <Update.h>
#include <ArduinoOTA.h>
#include <Preferences.h>
#include <SPI.h>
#include <Wire.h>
#include <SPIFFS.h>
#include <FS.h>
#include <esp_system.h>

#if __has_include(<LittleFS.h>)
#include <LittleFS.h>
#endif
#if __has_include(<NetworkClient.h>)          // core 3.x networking split
#include <NetworkClient.h>
#endif
#if __has_include(<BLEDevice.h>)
#include <BLEDevice.h>
#include <BLEServer.h>
#include <BLEUtils.h>
#endif
#if __has_include(<ArduinoJson.h>)
#include <ArduinoJson.h>
#endif
#if __has_include(<PubSubClient.h>)
#include <PubSubClient.h>
#endif
#if __has_include(<WebSocketsClient.h>)
#include <WebSocketsClient.h>
#include <WebSocketsServer.h>
#endif
#if __has_include(<Adafruit_NeoPixel.h>)
#include <Adafruit_NeoPixel.h>
#endif
#if __has_include(<FastLED.h>)
#include <FastLED.h>
#endif
#if __has_include(<Adafruit_GFX.h>)
#include <Adafruit_GFX.h>
#endif
#if __has_include(<Adafruit_SSD1306.h>)
#include <Adafruit_SSD1306.h>
#endif
#if __has_include(<DHT.h>)
#include <DHT.h>
#endif
#if __has_include(<OneWire.h>)
#include <OneWire.h>
#endif
#if __has_include(<DallasTemperature.h>)
#include <DallasTemperature.h>
#endif
#if __has_include(<NimBLEDevice.h>)
#include <NimBLEDevice.h>
#endif

// Kept volatile and global so nothing below is optimised away as dead.
volatile uint32_t sink = 0;

static void touchCore() {
  WiFi.mode(WIFI_STA);
  WiFi.begin("ssid", "password");
  sink += WiFi.status();
  sink += WiFi.localIP()[0];
  sink += WiFi.RSSI();
  WiFi.softAP("ap", "password");
  WiFi.scanNetworks();
  WiFi.disconnect();

  WiFiClient client;
  sink += client.connect("example.invalid", 80);
  client.println("GET / HTTP/1.0");
  sink += client.available();
  client.stop();

  WiFiUDP udp;
  udp.begin(1234);
  udp.beginPacket("example.invalid", 1234);
  udp.write((const uint8_t *)"x", 1);
  udp.endPacket();

  HTTPClient http;
  http.begin("http://example.invalid/");
  sink += http.GET();
  http.end();

  WiFiClientSecure tls;
  tls.setInsecure();
  sink += tls.connect("example.invalid", 443);

  static WebServer server(80);
  server.on("/", []() { sink += 1; });
  server.begin();
  server.handleClient();

  MDNS.begin("espfw");
  ArduinoOTA.setHostname("espfw");
  ArduinoOTA.begin();

  Preferences prefs;
  prefs.begin("espfw", false);
  prefs.putUInt("k", 1);
  sink += prefs.getUInt("k", 0);
  prefs.end();

  SPI.begin();
  SPI.transfer(0x5A);
  Wire.begin();
  Wire.beginTransmission(0x40);
  Wire.write(0x01);
  Wire.endTransmission();

  SPIFFS.begin(true);
  File f = SPIFFS.open("/x", FILE_WRITE);
  if (f) { f.println("x"); f.close(); }

#if __has_include(<LittleFS.h>)
  LittleFS.begin(true);
#endif

  sink += esp_get_free_heap_size();
  sink += (uint32_t)esp_random();

  Serial.printf("%lu %s %f\n", (unsigned long)sink, "s", 1.5);
  sink += String(sink).length();
  sink += String("x").toInt();
}

static void touchLibraries() {
#if __has_include(<ArduinoJson.h>)
  {
    JsonDocument doc;
    doc["a"] = 1;
    doc["b"] = "two";
    String out;
    serializeJson(doc, out);
    sink += out.length();
    deserializeJson(doc, "{\"a\":2}");
  }
#endif
#if __has_include(<PubSubClient.h>)
  {
    static WiFiClient net;
    static PubSubClient mqtt(net);
    mqtt.setServer("example.invalid", 1883);
    mqtt.connect("espfw");
    mqtt.publish("t", "p");
    mqtt.subscribe("t");
    mqtt.loop();
  }
#endif
#if __has_include(<WebSocketsClient.h>)
  {
    static WebSocketsClient ws;
    ws.begin("example.invalid", 81, "/");
    ws.loop();
    static WebSocketsServer wss(81);
    wss.begin();
    wss.loop();
  }
#endif
#if __has_include(<Adafruit_NeoPixel.h>)
  {
    static Adafruit_NeoPixel px(8, 5, NEO_GRB + NEO_KHZ800);
    px.begin();
    px.setPixelColor(0, px.Color(1, 2, 3));
    px.show();
  }
#endif
#if __has_include(<FastLED.h>)
  {
    static CRGB leds[8];
    FastLED.addLeds<WS2812, 5, GRB>(leds, 8);
    FastLED.setBrightness(64);
    FastLED.show();
  }
#endif
#if __has_include(<Adafruit_SSD1306.h>)
  {
    static Adafruit_SSD1306 oled(128, 64, &Wire, -1);
    oled.begin(SSD1306_SWITCHCAPVCC, 0x3C);
    oled.clearDisplay();
    oled.setCursor(0, 0);
    oled.print("espfw");
    oled.display();
  }
#endif
#if __has_include(<DHT.h>)
  {
    static DHT dht(4, DHT22);
    dht.begin();
    sink += (uint32_t)dht.readTemperature();
    sink += (uint32_t)dht.readHumidity();
  }
#endif
#if __has_include(<OneWire.h>) && __has_include(<DallasTemperature.h>)
  {
    static OneWire bus(4);
    static DallasTemperature sensors(&bus);
    sensors.begin();
    sensors.requestTemperatures();
    sink += (uint32_t)sensors.getTempCByIndex(0);
  }
#endif
#if __has_include(<BLEDevice.h>)
  {
    BLEDevice::init("espfw");
    BLEServer *s = BLEDevice::createServer();
    if (s) {
      BLEService *svc = s->createService("180a");
      if (svc) { svc->start(); }
    }
    BLEDevice::getAdvertising()->start();
  }
#endif
#if __has_include(<NimBLEDevice.h>)
  {
    NimBLEDevice::init("espfw");
    NimBLEDevice::getAdvertising()->start();
  }
#endif
}

void setup() {
  Serial.begin(115200);
  touchCore();
  touchLibraries();
}

void loop() {
  delay(1000);
  sink++;
}
