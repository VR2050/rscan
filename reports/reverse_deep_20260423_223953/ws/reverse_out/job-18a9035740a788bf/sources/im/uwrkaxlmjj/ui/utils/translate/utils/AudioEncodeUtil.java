package im.uwrkaxlmjj.ui.utils.translate.utils;

import im.uwrkaxlmjj.ui.utils.translate.common.AudioEditConstant;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;

/* JADX INFO: loaded from: classes5.dex */
public class AudioEncodeUtil {
    public static void convertWav2Pcm(String inWaveFilePath, String outPcmFilePath) {
        FileInputStream in = null;
        FileOutputStream out = null;
        byte[] data = new byte[1024];
        try {
            try {
                try {
                    in = new FileInputStream(inWaveFilePath);
                    out = new FileOutputStream(outPcmFilePath);
                    byte[] header = new byte[44];
                    in.read(header);
                    while (true) {
                        int length = in.read(data);
                        if (length > 0) {
                            out.write(data, 0, length);
                        } else {
                            try {
                                break;
                            } catch (IOException e) {
                                e.printStackTrace();
                            }
                        }
                    }
                    in.close();
                    out.close();
                } catch (Exception e2) {
                    e2.printStackTrace();
                    if (in != null) {
                        try {
                            in.close();
                        } catch (IOException e3) {
                            e3.printStackTrace();
                        }
                    }
                    if (out != null) {
                        out.close();
                    }
                }
            } catch (IOException e4) {
                e4.printStackTrace();
            }
        } catch (Throwable th) {
            if (in != null) {
                try {
                    in.close();
                } catch (IOException e5) {
                    e5.printStackTrace();
                }
            }
            if (out == null) {
                throw th;
            }
            try {
                out.close();
                throw th;
            } catch (IOException e6) {
                e6.printStackTrace();
                throw th;
            }
        }
    }

    public static void convertPcm2Wav(String inPcmFilePath, String outWavFilePath) {
        convertPcm2Wav(inPcmFilePath, outWavFilePath, AudioEditConstant.ExportSampleRate, 1, 16);
    }

    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:17:0x003d -> B:52:0x0057). Please report as a decompilation issue!!! */
    public static void convertPcm2Wav(String inPcmFilePath, String outWavFilePath, int sampleRate, int channels, int bitNum) {
        FileInputStream in = null;
        FileOutputStream out = null;
        byte[] data = new byte[1024];
        try {
            try {
                try {
                    in = new FileInputStream(inPcmFilePath);
                    out = new FileOutputStream(outWavFilePath);
                    long totalAudioLen = in.getChannel().size();
                    writeWaveFileHeader(out, totalAudioLen, sampleRate, channels, bitNum);
                    while (true) {
                        int length = in.read(data);
                        if (length > 0) {
                            out.write(data, 0, length);
                        } else {
                            try {
                                break;
                            } catch (IOException e) {
                                e.printStackTrace();
                            }
                        }
                    }
                    in.close();
                    out.close();
                } finally {
                }
            } catch (Exception e2) {
                e2.printStackTrace();
                if (in != null) {
                    try {
                        in.close();
                    } catch (IOException e3) {
                        e3.printStackTrace();
                    }
                }
                if (out == null) {
                } else {
                    out.close();
                }
            }
        } catch (IOException e4) {
            e4.printStackTrace();
        }
    }

    private static void writeWaveFileHeader(FileOutputStream out, long totalAudioLen, int sampleRate, int channels, int bitNum) throws IOException {
        byte[] header = getWaveHeader(totalAudioLen, sampleRate, channels, bitNum);
        out.write(header, 0, 44);
    }

    public static byte[] getWaveHeader(long totalAudioLen, int sampleRate, int channels, int bitNum) throws IOException {
        long totalDataLen = totalAudioLen + 36;
        long byteRate = ((sampleRate * channels) * bitNum) / 8;
        byte[] header = {82, 73, 70, 70, (byte) (totalDataLen & 255), (byte) ((totalDataLen >> 8) & 255), (byte) ((totalDataLen >> 16) & 255), (byte) ((totalDataLen >> 24) & 255), 87, 65, 86, 69, 102, 109, 116, 32, 16, 0, 0, 0, 1, 0, (byte) channels, 0, (byte) (sampleRate & 255), (byte) ((sampleRate >> 8) & 255), (byte) ((sampleRate >> 16) & 255), (byte) ((sampleRate >> 24) & 255), (byte) (byteRate & 255), (byte) ((byteRate >> 8) & 255), (byte) ((byteRate >> 16) & 255), (byte) ((byteRate >> 24) & 255), (byte) ((channels * 16) / 8), 0, 16, 0, 100, 97, 116, 97, (byte) (totalAudioLen & 255), (byte) ((totalAudioLen >> 8) & 255), (byte) ((totalAudioLen >> 16) & 255), (byte) ((totalAudioLen >> 24) & 255)};
        return header;
    }

    /* JADX WARN: Removed duplicated region for block: B:35:0x0114 A[Catch: Exception -> 0x0197, IOException -> 0x01a1, TRY_LEAVE, TryCatch #13 {IOException -> 0x01a1, Exception -> 0x0197, blocks: (B:24:0x00ce, B:33:0x010c, B:35:0x0114), top: B:84:0x00ce }] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static void convertPcm2Acc(java.lang.String r26, java.lang.String r27, int r28, int r29, int r30) {
        /*
            Method dump skipped, instruction units count: 501
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.ui.utils.translate.utils.AudioEncodeUtil.convertPcm2Acc(java.lang.String, java.lang.String, int, int, int):void");
    }

    private static void addADTStoPacket(byte[] packet, int packetLen) {
        packet[0] = -1;
        packet[1] = -7;
        packet[2] = (byte) (((2 - 1) << 6) + (4 << 2) + (2 >> 2));
        packet[3] = (byte) (((2 & 3) << 6) + (packetLen >> 11));
        packet[4] = (byte) ((packetLen & 2047) >> 3);
        packet[5] = (byte) (((packetLen & 7) << 5) + 31);
        packet[6] = -4;
    }

    private static long computePresentationTime(long frameIndex) {
        return ((90000 * frameIndex) * 1024) / 44100;
    }
}
