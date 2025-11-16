import {getWifiData} from "./DecodeTuyaLink.js";

/**
 * Tuya's specific CRC8 implementation.
 * @private
 */
function tuyaCRC8(bytes) {
  let crc = 0;
  for (const b of bytes) {
    crc ^= b;
    for (let i = 0; i < 8; i++) {
      if (crc & 0x80) {
        crc = (crc << 1) ^ 0x07;
      } else {
        crc <<= 1;
      }
    }
  }
  return crc & 0xFF;
}

class TuyaLinkEncoder {
  /**
   * Helper method to get the byte length of a string or buffer.
   * @private
   */
  _getLength(data) {
    if (Buffer.isBuffer(data)) {
      return data.length;
    }
    return Buffer.byteLength(data);
  }

  /**
   * Helper method to round a number up to the nearest multiple of another.
   * @private
   */
  _rounder(num, mult) {
    return Math.ceil(num / mult) * mult;
  }

  /**
   * Encodes data as UDP packet lengths.
   *
   * encodedData:
   * rawByteArray = [wifiPassword length | wifiPassword | regionTokenSecret length | regionTokenSecret | ssid]
   *
   * Header:
   * [rawByteArray length high | rawByteArray length low | CRC from length high | crc from length low]
   *
   * Body:
   * [CRC from next 5 bits | index bit | rawByteArray | rawByteArray | rawByteArray | rawByteArray]
   * Body structure is repeated until rawByteArray is exhausted
   * rawByteArray value can be 0 if no values are left
   *
   * before this encoded data is transmitted, the following packets are send repeatedly until encodedData gets broadcasted:
   * udp packet of length: 1, 3, 6, 10
   */
  smartLinkEncode(options) {
    console.log("Wifi Pass: " + options.wifiPassword)
    console.log("Wifi SSID: " + options.ssid)
    console.log("Region: " + options.region)
    console.log("Wifi Token: " + options.token)
    console.log("Wifi Secret: " + options.secret + "\n")
    // Buffer = ByteArray
    const wifiPasswordBytes = Buffer.from(options.wifiPassword);
    const regionTokenSecretBytes = Buffer.from(
        options.region +
        options.token +
        options.secret);
    const ssidBytes = Buffer.from(options.ssid);

    // Calculate size of byte array
    // (must add 1 byte for lengths)
    // [Pass_Len][Pass_Data][RTS_Len][RTS_Data][SSID_Data]
    const rawByteArray = Buffer.alloc(1 +
        wifiPasswordBytes.length +
        1 +
        regionTokenSecretBytes.length +
        ssidBytes.length);

    let rawByteArrayIndex = 0;

    // Write WiFi password length
    rawByteArray.writeInt8(this._getLength(options.wifiPassword), rawByteArrayIndex);
    rawByteArrayIndex++;

    // Write WiFi password
    wifiPasswordBytes.copy(rawByteArray, rawByteArrayIndex);
    rawByteArrayIndex += wifiPasswordBytes.length;

    // Write region token secret length
    rawByteArray.writeInt8(this._getLength(regionTokenSecretBytes), rawByteArrayIndex);
    rawByteArrayIndex++;

    // Write region token secret bytes
    regionTokenSecretBytes.copy(rawByteArray, rawByteArrayIndex);
    rawByteArrayIndex += regionTokenSecretBytes.length;

    // Write WiFi SSID bytes
    ssidBytes.copy(rawByteArray, rawByteArrayIndex);
    rawByteArrayIndex += ssidBytes.length;

    if (rawByteArray.length !== rawByteArrayIndex) {
      throw new Error('Byte buffer filled improperly');
    }

    // Now, encode above data into packet lengths
    const rawDataLengthRoundedUp = this._rounder(rawByteArray.length, 4);

    const encodedData = [];

    // First 4 bytes of header
    const stringLength = (wifiPasswordBytes.length +
        regionTokenSecretBytes.length + ssidBytes.length + 2) % 256;
    const stringLengthCRC = tuyaCRC8([stringLength]);

    // Length encoded into the first two bytes based at 16 and then 32
    encodedData[0] = (stringLength / 16) | 16;
    encodedData[1] = (stringLength % 16) | 32;
    // Length CRC encoded into the next two bytes based at 48 and 64
    encodedData[2] = (stringLengthCRC / 16) | 48;
    encodedData[3] = (stringLengthCRC % 16) | 64;
    console.log("Header:");
    console.log("[High Length | Low Length | High CRC | Low CRC]");
    console.log(`[${encodedData.join(" | ")}]`);

    // Rest of data
    let encodedDataIndex = 4;
    let sequenceCounter = 0;

    // structure: [index from 0][4Bit rawByteArray]
    // if rawByteArray doesn't have 4 Bit left, use 0 instead
    // 0,8,97,97,97 | 1,97,99,99,99 | 2,99,14,69,85 | ... | 6,97,97,0,0
    for (let x = 0; x < rawDataLengthRoundedUp; x += 4) {
      console.log("-------------- Index: " + x + " --------------");
      // Build CRC buffer, using data from rawByteArray or 0 values if too long
      const crcData = [];
      crcData[0] = sequenceCounter++;
      crcData[1] = x + 0 < rawByteArray.length ? rawByteArray[x + 0] : 0;
      crcData[2] = x + 1 < rawByteArray.length ? rawByteArray[x + 1] : 0;
      crcData[3] = x + 2 < rawByteArray.length ? rawByteArray[x + 2] : 0;
      crcData[4] = x + 3 < rawByteArray.length ? rawByteArray[x + 3] : 0;
      console.log("CRC Buffer: " + crcData);

      // Calculate the CRC
      const crc = tuyaCRC8(crcData);

      // Move data to encodedData array
      // CRC
      encodedData[encodedDataIndex++] = (crc % 128) | 128;

      // Sequence number
      encodedData[encodedDataIndex++] = (crcData[0] % 128) | 128;
      // Data
      encodedData[encodedDataIndex++] = (crcData[1] % 256) | 256;
      encodedData[encodedDataIndex++] = (crcData[2] % 256) | 256;
      encodedData[encodedDataIndex++] = (crcData[3] % 256) | 256;
      encodedData[encodedDataIndex++] = (crcData[4] % 256) | 256;
      console.log("Body Chunk:");
      console.log("[CRC | Index | Data | Data | Data | Data]");
      console.log(`[${encodedData.slice(encodedDataIndex - 6, encodedDataIndex).join(" | ")}]`);
    }

    return encodedData;
  }
}

// ---  Usage ---
const encoder = new TuyaLinkEncoder();

const options = {
  region: 'EU',
  token: '00000000',
  secret: '0101',
  ssid: 'aaaa',
  wifiPassword: 'aaaacccc'
};

const options2 = {
  region: 'EU',
  token: '00000000',
  secret: '0101',
  ssid: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
  wifiPassword: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaPass'
};

try {
  const encodedData = encoder.smartLinkEncode(options2);
  console.log("Encoded Data length: ", encodedData.length);
  getWifiData(encodedData);


} catch (error) {
  console.error('Failed to encode data:', error.message);
}
