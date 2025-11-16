import * as path from "node:path";
import * as fs from "node:fs";

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

// decodes the encoded Header data
// contains length and crc of length
// length: wifiPasswordBytes + regionTokenSecretBytes + ssidBytes + 2 (for wifiPasswordBytes and regionTokenSecretBytes length)
function getHeaderData(encodedData) {
    // the marker is a number represented as the higher 4 bits
    // the actual data is represented as the lower 4 bits
    const highLengthHeaderByte = encodedData[0]; // its: marker: 16
    const lowLengthHeaderByte = encodedData[1]; // its marker: 32
    const highCRCHeaderByte = encodedData[2]; // its marker: 48
    const lowCRCHeaderByte = encodedData[3]; // its marker: 64

    // isolates higher 4 bits (e.g. 1111_0000)
    const HIGH_MASK = 0xF0;
    try {
        // check if markers are correct
        console.assert((highLengthHeaderByte & HIGH_MASK) === 0x10, "Header Marker (16) not found")
        console.assert((lowLengthHeaderByte & HIGH_MASK) === 0x20, "Header Marker (32) not found")
        console.assert((highCRCHeaderByte & HIGH_MASK) === 0x30, "Header Marker (48) not found")
        console.assert((lowCRCHeaderByte & HIGH_MASK) === 0x40, "Header Marker (64) not found")
    } catch (error) {
        console.error("Marker for Header (Length and CRC) incorrect: " + error);
        return false;
    }
    // isolates lower 4 bits (e.g. 0000_1111)
    const LOW_MASK = 0x0F;

    // strip the markers
    const highLengthHeader = highLengthHeaderByte & LOW_MASK;
    const lowLengthHeader = lowLengthHeaderByte & LOW_MASK;
    const highCRCHeader = highCRCHeaderByte & LOW_MASK;
    const lowCRCHeader = lowCRCHeaderByte & LOW_MASK;

    const lengthHeader = highLengthHeader * 16 + lowLengthHeader;
    const crcHeader = highCRCHeader * 16 + lowCRCHeader;

    // TODO() verify integrity of length via CRC
    return [lengthHeader, crcHeader];
}

// decode and print following structure:
// [Pass_Len][Pass_Data][RTS_Len][RTS_Data][SSID_Data]
// TODO() split RTS
function decodeRawByteArray(rawByteArray) {
    // find wifi password using length
    const passLength = rawByteArray[0];
    let wifiPassword = "";
    for (let i = 1; i < passLength + 1; i++) {
        wifiPassword += String.fromCharCode(rawByteArray[i]);
    }
    console.assert(wifiPassword.length === passLength);
    console.log("Decoded WifiPass: " + wifiPassword);

    // find rts using length
    let indexOffset = passLength + 1;
    const rtsLength = rawByteArray[indexOffset]
    let rts = "";
    for (let i = indexOffset + 1; i < indexOffset + rtsLength + 1; i++) {
        rts += String.fromCharCode(rawByteArray[i]);
    }
    console.assert(rts.length === rtsLength);
    const region = rts.slice(0, 2);
    const token = rts.slice(2, 10);
    const secret = rts.slice(10, 14);
    console.log("Decoded Region:", region);
    console.log("Decoded Token:", token);
    console.log("Decoded Secret:", secret);

    // find wifi ssid using everything left
    indexOffset = indexOffset + rtsLength + 1;
    let wifiSSID = "";
    for (let i = indexOffset; i < rawByteArray.length; i++) {
        wifiSSID += String.fromCharCode(rawByteArray[i]);
    }
    // total length - password length - rts length - the two length numbers
    console.assert(wifiSSID.length === rawByteArray.length - passLength - rtsLength - 2);
    console.log("Decoded SSID: " + wifiSSID);
}

// [CRC from next 5 bits | index bit | rawByteArray | rawByteArray | rawByteArray | rawByteArray]
// CRC consists of the index and 4 data bytes
function extractRawByteArray(encodedData, headerLength) {
    // strip Headers
    let encodedDataBody = encodedData.slice(4)

    // calculate end of sequence
    // divide by 4 since there are 4 data bytes per index increment
    // multiply by 6 since there are 6 bytes per body row: CRC, index, 4 data bytes
    const lastByteIndex = Math.ceil(headerLength / 4) * 6

    const extractedRawByteArray = []
    // the index is a number starting from 0 and getting incremented by 1 for each body "section"
    let expectedSequenceCounter = 0;
    for (let i = 0; i < lastByteIndex - 1; i += 6) {
        const receivedCRC = encodedDataBody[i];
        // verify markers
        const HIGH_MASK = 0b1111_1000_0000;
        console.assert((encodedDataBody[i + 1] & HIGH_MASK) === 128, " Body Marker (128) for Index found: ", encodedDataBody[i + 1] & HIGH_MASK)
        console.assert((encodedDataBody[i + 2] & HIGH_MASK) === 256, "Body Marker (256) for Data-1 found: ", encodedDataBody[i + 2] & HIGH_MASK)
        console.assert((encodedDataBody[i + 3] & HIGH_MASK) === 256, "Body Marker (256) for Data-2 found: ", encodedDataBody[i + 3] & HIGH_MASK)
        console.assert((encodedDataBody[i + 4] & HIGH_MASK) === 256, "Body Marker (256) for Data-3 found: ", encodedDataBody[i + 4] & HIGH_MASK)
        console.assert((encodedDataBody[i + 5] & HIGH_MASK) === 256, "Body Marker (256) for Data-4 found: ", encodedDataBody[i + 5] & HIGH_MASK)

        const index = encodedDataBody[i + 1] - 128;
        const data1 = encodedDataBody[i + 2] - 256;
        const data2 = encodedDataBody[i + 3] - 256;
        const data3 = encodedDataBody[i + 4] - 256;
        const data4 = encodedDataBody[i + 5] - 256;

        // verify crc
        const recreatedCRC = tuyaCRC8([index, data1, data2, data3, data4]);
        // % 128 | 128 recreates and applies the marker
        console.assert(((recreatedCRC % 128) | 128) === (receivedCRC) % 128 | 128, `CRC check failed: found ${receivedCRC} recreated: ${recreatedCRC}`);
        // verify index
        console.assert(index === expectedSequenceCounter, `Index check failed: found ${index}, expected: ${expectedSequenceCounter}`);
        expectedSequenceCounter++
        extractedRawByteArray.push(data1, data2 , data3 , data4 );
    }
    return extractedRawByteArray;
}

export function getWifiData(encodedData) {
    const [headerLength, headerCRC] = getHeaderData(encodedData)
    const extractedRawByteArray = extractRawByteArray(encodedData, headerLength);
    decodeRawByteArray(extractedRawByteArray);
}

function parsePackets() {
    const filteredPacketsLength = []
    const absolutePath = path.resolve("./resources/output.json");

    const fileContent = fs.readFileSync(absolutePath, 'utf8');
    const packets = JSON.parse(fileContent);

    packets.forEach(packet => {
        // TODO() filter for udp packet and ip.dst == 255.255.255.255
        // get packet data length
        const length = parseInt(packet._source.layers.data["data.len"]);
        filteredPacketsLength.push(length);
    });

    // before this encoded data is transmitted, the following packets are send repeatedly until encodedData gets broadcasted:
    // udp packet of length: 1, 3, 6, 10
    // after the encoded date is transmitted, packets of length 1 follow
    let beginningIndex = undefined;
    for (let i = 0; i < filteredPacketsLength.length - 4; i++) {
        if (filteredPacketsLength[i + 0] !== 1) continue;
        if (filteredPacketsLength[i + 1] !== 3) continue;
        if (filteredPacketsLength[i + 2] !== 6) continue;
        if (filteredPacketsLength[i + 3] !== 10) continue;
        if (filteredPacketsLength[i + 4] === 1) continue;
        beginningIndex = i+4;
    }
    console.assert(beginningIndex, "Beginning of Raw Byte Array not found")
    const rawByteArray = filteredPacketsLength.slice(beginningIndex);
    getWifiData(rawByteArray);

}

parsePackets()