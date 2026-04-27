package im.uwrkaxlmjj.ui.utils.translate;

import android.media.MediaCodec;
import android.media.MediaCrypto;
import android.media.MediaExtractor;
import android.media.MediaFormat;
import android.text.TextUtils;
import android.view.Surface;
import com.google.android.exoplayer2.source.hls.DefaultHlsExtractorFactory;
import com.google.android.exoplayer2.util.MimeTypes;
import com.google.firebase.remoteconfig.FirebaseRemoteConfig;
import im.uwrkaxlmjj.messenger.ApplicationLoader;
import im.uwrkaxlmjj.messenger.FileLog;
import im.uwrkaxlmjj.ui.utils.translate.callback.DecodeOperateInterface;
import im.uwrkaxlmjj.ui.utils.translate.common.AudioEditConstant;
import im.uwrkaxlmjj.ui.utils.translate.ssrc.SSRC;
import im.uwrkaxlmjj.ui.utils.translate.utils.AudioBitUtils;
import im.uwrkaxlmjj.ui.utils.translate.utils.AudioEncodeUtil;
import im.uwrkaxlmjj.ui.utils.translate.utils.AudioFileUtils;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import kotlin.UByte;

/* JADX INFO: loaded from: classes5.dex */
public class DecodeEngine {
    private static DecodeEngine instance;
    private String TAG = DecodeEngine.class.getSimpleName();

    private DecodeEngine() {
    }

    public static DecodeEngine getInstance() {
        if (instance == null) {
            synchronized (DecodeEngine.class) {
                if (instance == null) {
                    instance = new DecodeEngine();
                }
            }
        }
        return instance;
    }

    public boolean convertMusicFileToWaveFile(String musicFileUrl, String decodeFileUrl, DecodeOperateInterface decodeOperateInterface) {
        boolean success = decodeMusicFile(musicFileUrl, decodeFileUrl, 1, -1L, -1L, decodeOperateInterface);
        if (decodeOperateInterface != null) {
            if (success) {
                decodeOperateInterface.decodeSuccess();
            } else {
                decodeOperateInterface.decodeFail();
            }
        }
        return success;
    }

    public boolean convertMusicFileToWaveFile(String musicFileUrl, String decodeFileUrl, double startSecond, double endSecond, DecodeOperateInterface decodeOperateInterface) {
        boolean success = decodeMusicFile(musicFileUrl, decodeFileUrl, 1, ((long) startSecond) * 1000000, ((long) endSecond) * 1000000, decodeOperateInterface);
        if (decodeOperateInterface != null) {
            if (success) {
                decodeOperateInterface.decodeSuccess();
            } else {
                decodeOperateInterface.decodeFail();
            }
        }
        return success;
    }

    public boolean convertMusicFileToAccFile(String musicFileUrl, String decodeFileUrl, DecodeOperateInterface decodeOperateInterface) {
        boolean success = decodeMusicFile(musicFileUrl, decodeFileUrl, 2, -1L, -1L, decodeOperateInterface);
        if (decodeOperateInterface != null) {
            if (success) {
                decodeOperateInterface.decodeSuccess();
            } else {
                decodeOperateInterface.decodeFail();
            }
        }
        return success;
    }

    public boolean convertMusicFileToPcmFile(String musicFileUrl, String decodeFileUrl, DecodeOperateInterface decodeOperateInterface) {
        boolean success = decodeMusicFile(musicFileUrl, decodeFileUrl, 0, -1L, -1L, decodeOperateInterface);
        if (decodeOperateInterface != null) {
            if (success) {
                decodeOperateInterface.decodeSuccess();
            } else {
                decodeOperateInterface.decodeFail();
            }
        }
        return success;
    }

    public boolean convertMusicFileToPcmFile(String musicFileUrl, String decodeFileUrl, int startSecond, int endSecond, DecodeOperateInterface decodeOperateInterface) {
        boolean success = decodeMusicFile(musicFileUrl, decodeFileUrl, 0, ((long) startSecond) * 1000000, ((long) endSecond) * 1000000, decodeOperateInterface);
        if (decodeOperateInterface != null) {
            if (success) {
                decodeOperateInterface.decodeSuccess();
            } else {
                decodeOperateInterface.decodeFail();
            }
        }
        return success;
    }

    private boolean decodeMusicFile(String musicFileUrl, String decodeFileUrl, int convertType, long startMicroseconds, long endMicroseconds, DecodeOperateInterface decodeOperateInterface) {
        int bitNumber;
        MediaCodec mediaCodec;
        MediaExtractor mediaExtractor = new MediaExtractor();
        try {
            mediaExtractor.setDataSource(musicFileUrl);
        } catch (Exception ex) {
            ex.printStackTrace();
            try {
                mediaExtractor.setDataSource(new FileInputStream(musicFileUrl).getFD());
            } catch (Exception e) {
                e.printStackTrace();
                FileLog.e("设置解码音频文件路径错误");
            }
        }
        if (mediaExtractor.getTrackCount() <= 0) {
            FileLog.e("解码器出错");
            return false;
        }
        MediaFormat mediaFormat = mediaExtractor.getTrackFormat(0);
        int sampleRate = mediaFormat.containsKey("sample-rate") ? mediaFormat.getInteger("sample-rate") : 44100;
        int channelCount = mediaFormat.containsKey("channel-count") ? mediaFormat.getInteger("channel-count") : 1;
        long duration = mediaFormat.containsKey("durationUs") ? mediaFormat.getLong("durationUs") : 0L;
        String mime = mediaFormat.containsKey("mime") ? mediaFormat.getString("mime") : "";
        int pcmEncoding = mediaFormat.containsKey("pcm-encoding") ? mediaFormat.getInteger("pcm-encoding") : 2;
        if (pcmEncoding == 3) {
            bitNumber = 8;
        } else if (pcmEncoding == 4) {
            bitNumber = 32;
        } else {
            bitNumber = 16;
        }
        FileLog.e("歌曲信息Track info: mime:" + mime + " 采样率sampleRate:" + sampleRate + " channels:" + channelCount + " duration:" + duration);
        if (TextUtils.isEmpty(mime) || !mime.startsWith("audio/")) {
            FileLog.e("解码文件不是音频文件mime:" + mime);
            return false;
        }
        if (mime.equals("audio/ffmpeg")) {
            mime = MimeTypes.AUDIO_MPEG;
            mediaFormat.setString("mime", MimeTypes.AUDIO_MPEG);
        }
        if (duration <= 0) {
            FileLog.e("音频文件duration为" + duration);
            return false;
        }
        long startMicroseconds2 = Math.max(startMicroseconds, 0L);
        long endMicroseconds2 = Math.min(endMicroseconds < 0 ? duration : endMicroseconds, duration);
        if (startMicroseconds2 >= endMicroseconds2) {
            return false;
        }
        try {
            mediaCodec = MediaCodec.createDecoderByType(mime);
        } catch (Exception e2) {
        }
        try {
            mediaCodec.configure(mediaFormat, (Surface) null, (MediaCrypto) null, 0);
            String decodeFileUrl2 = decodeFileUrl.substring(0, decodeFileUrl.lastIndexOf("."));
            String pcmFilePath = decodeFileUrl2 + ".pcm";
            getDecodeData(mediaExtractor, mediaCodec, pcmFilePath, sampleRate, channelCount, startMicroseconds2, endMicroseconds2, decodeOperateInterface);
            if (convertType == 1) {
                String convertFilePath = decodeFileUrl2 + ".wav";
                convertPcmFileToWaveFile(pcmFilePath, convertFilePath, sampleRate, channelCount, bitNumber);
                new File(pcmFilePath).delete();
            } else if (convertType == 2) {
                String convertFilePath2 = decodeFileUrl2 + DefaultHlsExtractorFactory.AAC_FILE_EXTENSION;
                convertPcmFileToAccFile(pcmFilePath, convertFilePath2, sampleRate, channelCount, bitNumber);
                new File(pcmFilePath).delete();
            }
            return true;
        } catch (Exception e3) {
            FileLog.e("解码器configure出错");
            return false;
        }
    }

    private void convertPcmFileToWaveFile(String pcmFilePath, String convertFilePath, int sampleRate, int channels, int bitNumber) {
        AudioEncodeUtil.convertPcm2Wav(pcmFilePath, convertFilePath, sampleRate, channels, bitNumber);
    }

    private void convertPcmFileToAccFile(String pcmFilePath, String convertFilePath, int sampleRate, int channels, int bitNumber) {
        if (AudioFileUtils.checkFileExist(convertFilePath)) {
            AudioFileUtils.deleteFile(new File(convertFilePath));
        }
        AudioFileUtils.confirmFolderExist(new File(convertFilePath).getParent());
        AudioEncodeUtil.convertPcm2Acc(pcmFilePath, convertFilePath, sampleRate, channels, bitNumber);
    }

    private void getDecodeData(MediaExtractor mediaExtractor, MediaCodec mediaCodec, String decodeFileUrl, int sampleRate, int channelCount, long startMicroseconds, long endMicroseconds, DecodeOperateInterface decodeOperateInterface) {
        BufferedOutputStream bufferedOutputStream;
        int sampleRate2;
        long decodeNoticeTime;
        MediaCodec.BufferInfo bufferInfo;
        long presentationTimeUs;
        int sampleDataSize;
        boolean decodeInputEnd;
        long j;
        BufferedOutputStream bufferedOutputStream2;
        DecodeEngine decodeEngine = this;
        long decodeNoticeTime2 = System.currentTimeMillis();
        MediaFormat outputFormat = mediaCodec.getOutputFormat();
        int integer = (outputFormat.containsKey("bit-width") ? outputFormat.getInteger("bit-width") : 0) / 8;
        mediaCodec.start();
        ByteBuffer[] inputBuffers = mediaCodec.getInputBuffers();
        ByteBuffer[] outputBuffers = mediaCodec.getOutputBuffers();
        mediaExtractor.selectTrack(0);
        MediaCodec.BufferInfo bufferInfo2 = new MediaCodec.BufferInfo();
        BufferedOutputStream bufferedOutputStream3 = AudioFileUtils.getBufferedOutputStreamFromFile(decodeFileUrl);
        long presentationTimeUs2 = 0;
        ByteBuffer[] outputBuffers2 = outputBuffers;
        long presentationTimeUs3 = decodeNoticeTime2;
        int sampleRate3 = sampleRate;
        int channelCount2 = channelCount;
        boolean decodeOutputEnd = false;
        boolean decodeInputEnd2 = false;
        while (true) {
            if (decodeOutputEnd) {
                bufferedOutputStream = bufferedOutputStream3;
                sampleRate2 = sampleRate3;
                break;
            }
            long decodeTime = System.currentTimeMillis();
            bufferedOutputStream = bufferedOutputStream3;
            long decodeNoticeTime3 = presentationTimeUs3;
            if (decodeTime - presentationTimeUs3 > 1000) {
                int decodeProgress = (int) (((presentationTimeUs2 - startMicroseconds) * 100) / endMicroseconds);
                if (decodeProgress > 0) {
                    decodeEngine.notifyProgress(decodeOperateInterface, decodeProgress);
                }
                decodeNoticeTime = decodeTime;
            } else {
                decodeNoticeTime = decodeNoticeTime3;
            }
            try {
                int inputBufferIndex = mediaCodec.dequeueInputBuffer(100L);
                if (inputBufferIndex >= 0) {
                    try {
                        ByteBuffer sourceBuffer = inputBuffers[inputBufferIndex];
                        int sampleDataSize2 = mediaExtractor.readSampleData(sourceBuffer, 0);
                        if (sampleDataSize2 < 0) {
                            presentationTimeUs = presentationTimeUs2;
                            sampleDataSize = 0;
                            decodeInputEnd = true;
                        } else {
                            presentationTimeUs = mediaExtractor.getSampleTime();
                            sampleDataSize = sampleDataSize2;
                            decodeInputEnd = decodeInputEnd2;
                        }
                        j = 100;
                        bufferedOutputStream2 = bufferedOutputStream;
                        sampleRate2 = sampleRate3;
                        int sampleRate4 = decodeInputEnd ? 4 : 0;
                        try {
                            mediaCodec.queueInputBuffer(inputBufferIndex, 0, sampleDataSize, presentationTimeUs, sampleRate4);
                            if (!decodeInputEnd) {
                                mediaExtractor.advance();
                            }
                            decodeInputEnd2 = decodeInputEnd;
                            presentationTimeUs2 = presentationTimeUs;
                        } catch (Exception e) {
                            e = e;
                            decodeInputEnd2 = decodeInputEnd;
                            bufferInfo = bufferInfo2;
                            presentationTimeUs2 = presentationTimeUs;
                            bufferedOutputStream = bufferedOutputStream2;
                            sampleRate3 = sampleRate2;
                            FileLog.e("getDecodeData异常" + e);
                            decodeEngine = this;
                            bufferInfo2 = bufferInfo;
                            bufferedOutputStream3 = bufferedOutputStream;
                            presentationTimeUs3 = decodeNoticeTime;
                        }
                    } catch (Exception e2) {
                        e = e2;
                        bufferInfo = bufferInfo2;
                    }
                } else {
                    j = 100;
                    bufferedOutputStream2 = bufferedOutputStream;
                    sampleRate2 = sampleRate3;
                }
                bufferInfo = bufferInfo2;
                try {
                    int outputBufferIndex = mediaCodec.dequeueOutputBuffer(bufferInfo, j);
                    if (outputBufferIndex >= 0) {
                        ByteBuffer targetBuffer = outputBuffers2[outputBufferIndex];
                        byte[] sourceByteArray = new byte[bufferInfo.size];
                        targetBuffer.get(sourceByteArray);
                        targetBuffer.clear();
                        mediaCodec.releaseOutputBuffer(outputBufferIndex, false);
                        if ((bufferInfo.flags & 4) != 0) {
                            decodeOutputEnd = true;
                        }
                        if (sourceByteArray.length > 0) {
                            bufferedOutputStream = bufferedOutputStream2;
                            if (bufferedOutputStream != null) {
                                if (presentationTimeUs2 < startMicroseconds) {
                                    decodeEngine = this;
                                    bufferInfo2 = bufferInfo;
                                    bufferedOutputStream3 = bufferedOutputStream;
                                    presentationTimeUs3 = decodeNoticeTime;
                                    sampleRate3 = sampleRate2;
                                } else {
                                    try {
                                        bufferedOutputStream.write(sourceByteArray);
                                    } catch (Exception e3) {
                                        try {
                                            FileLog.e("输出解压音频数据异常" + e3);
                                        } catch (Exception e4) {
                                            e = e4;
                                            sampleRate3 = sampleRate2;
                                            FileLog.e("getDecodeData异常" + e);
                                            decodeEngine = this;
                                            bufferInfo2 = bufferInfo;
                                            bufferedOutputStream3 = bufferedOutputStream;
                                            presentationTimeUs3 = decodeNoticeTime;
                                        }
                                    }
                                }
                            }
                        } else {
                            bufferedOutputStream = bufferedOutputStream2;
                        }
                        if (presentationTimeUs2 > endMicroseconds) {
                            break;
                        }
                        decodeEngine = this;
                        bufferInfo2 = bufferInfo;
                        bufferedOutputStream3 = bufferedOutputStream;
                        presentationTimeUs3 = decodeNoticeTime;
                        sampleRate3 = sampleRate2;
                    } else if (outputBufferIndex != -3) {
                        if (outputBufferIndex != -2) {
                            sampleRate3 = sampleRate2;
                        } else {
                            try {
                                MediaFormat outputFormat2 = mediaCodec.getOutputFormat();
                                try {
                                    int sampleRate5 = outputFormat2.containsKey("sample-rate") ? outputFormat2.getInteger("sample-rate") : sampleRate2;
                                    try {
                                        int channelCount3 = outputFormat2.containsKey("channel-count") ? outputFormat2.getInteger("channel-count") : channelCount2;
                                        try {
                                            int integer2 = (outputFormat2.containsKey("bitrate") ? outputFormat2.getInteger("bitrate") : 0) / 8;
                                            try {
                                                FileLog.e("MediaCodec.INFO_OUTPUT_FORMAT_CHANGED [AudioDecoder]output format has changed to " + mediaCodec.getOutputFormat());
                                                sampleRate3 = sampleRate5;
                                                channelCount2 = channelCount3;
                                            } catch (Exception e5) {
                                                e = e5;
                                                sampleRate3 = sampleRate5;
                                                channelCount2 = channelCount3;
                                                bufferedOutputStream = bufferedOutputStream2;
                                                FileLog.e("getDecodeData异常" + e);
                                                decodeEngine = this;
                                                bufferInfo2 = bufferInfo;
                                                bufferedOutputStream3 = bufferedOutputStream;
                                                presentationTimeUs3 = decodeNoticeTime;
                                            }
                                        } catch (Exception e6) {
                                            e = e6;
                                            sampleRate3 = sampleRate5;
                                            channelCount2 = channelCount3;
                                            bufferedOutputStream = bufferedOutputStream2;
                                        }
                                    } catch (Exception e7) {
                                        e = e7;
                                        sampleRate3 = sampleRate5;
                                        bufferedOutputStream = bufferedOutputStream2;
                                    }
                                } catch (Exception e8) {
                                    e = e8;
                                    bufferedOutputStream = bufferedOutputStream2;
                                    sampleRate3 = sampleRate2;
                                }
                            } catch (Exception e9) {
                                e = e9;
                                bufferedOutputStream = bufferedOutputStream2;
                                sampleRate3 = sampleRate2;
                            }
                        }
                        decodeEngine = this;
                        bufferInfo2 = bufferInfo;
                        presentationTimeUs3 = decodeNoticeTime;
                        bufferedOutputStream3 = bufferedOutputStream2;
                    } else {
                        ByteBuffer[] outputBuffers3 = mediaCodec.getOutputBuffers();
                        try {
                            FileLog.e("MediaCodec.INFO_OUTPUT_BUFFERS_CHANGED [AudioDecoder]output buffers have changed.");
                            outputBuffers2 = outputBuffers3;
                            sampleRate3 = sampleRate2;
                            decodeEngine = this;
                            bufferInfo2 = bufferInfo;
                            presentationTimeUs3 = decodeNoticeTime;
                            bufferedOutputStream3 = bufferedOutputStream2;
                        } catch (Exception e10) {
                            e = e10;
                            outputBuffers2 = outputBuffers3;
                            bufferedOutputStream = bufferedOutputStream2;
                            sampleRate3 = sampleRate2;
                            FileLog.e("getDecodeData异常" + e);
                            decodeEngine = this;
                            bufferInfo2 = bufferInfo;
                            bufferedOutputStream3 = bufferedOutputStream;
                            presentationTimeUs3 = decodeNoticeTime;
                        }
                    }
                } catch (Exception e11) {
                    e = e11;
                    bufferedOutputStream = bufferedOutputStream2;
                    sampleRate3 = sampleRate2;
                }
            } catch (Exception e12) {
                e = e12;
                bufferInfo = bufferInfo2;
            }
        }
        if (bufferedOutputStream != null) {
            try {
                bufferedOutputStream.close();
            } catch (IOException e13) {
                FileLog.e("关闭bufferedOutputStream异常" + e13);
            }
        }
        int sampleRate6 = sampleRate2;
        if (sampleRate6 != 16000) {
            Resample(sampleRate6, decodeFileUrl);
        }
        notifyProgress(decodeOperateInterface, 100);
        if (mediaCodec != null) {
            mediaCodec.stop();
            mediaCodec.release();
        }
        if (mediaExtractor != null) {
            mediaExtractor.release();
        }
    }

    private static void Resample(int sampleRate, String decodeFileUrl) {
        String fileParent = decodeFileUrl.substring(0, decodeFileUrl.lastIndexOf("."));
        String newDecodeFileUrl = fileParent + "_new.pcm";
        try {
            FileInputStream fileInputStream = new FileInputStream(new File(decodeFileUrl));
            FileOutputStream fileOutputStream = new FileOutputStream(new File(newDecodeFileUrl));
            new SSRC(fileInputStream, fileOutputStream, sampleRate, AudioEditConstant.ExportSampleRate, 2, 2, 1, Integer.MAX_VALUE, FirebaseRemoteConfig.DEFAULT_VALUE_FOR_DOUBLE, 0, true);
            fileInputStream.close();
            fileOutputStream.close();
            AudioFileUtils.renameFile(newDecodeFileUrl, decodeFileUrl);
        } catch (IOException e) {
            FileLog.e("关闭bufferedOutputStream异常" + e);
        }
    }

    public static byte[] convertByteNumber(int sourceByteNumber, int outputByteNumber, byte[] sourceByteArray) {
        if (sourceByteNumber == outputByteNumber) {
            return sourceByteArray;
        }
        int sourceByteArrayLength = sourceByteArray.length;
        if (sourceByteNumber == 0 || sourceByteNumber == 1) {
            if (outputByteNumber == 2) {
                byte[] byteArray = new byte[sourceByteArrayLength * 2];
                for (int index = 0; index < sourceByteArrayLength; index++) {
                    byte[] resultByte = AudioBitUtils.GetBytes((short) (sourceByteArray[index] * UByte.MIN_VALUE), AudioEditConstant.isBigEnding);
                    byteArray[index * 2] = resultByte[0];
                    byteArray[(index * 2) + 1] = resultByte[1];
                }
                return byteArray;
            }
        } else if (sourceByteNumber == 2 && outputByteNumber == 1) {
            int outputByteArrayLength = sourceByteArrayLength / 2;
            byte[] byteArray2 = new byte[outputByteArrayLength];
            for (int index2 = 0; index2 < outputByteArrayLength; index2++) {
                byteArray2[index2] = (byte) (AudioBitUtils.GetShort(sourceByteArray[index2 * 2], sourceByteArray[(index2 * 2) + 1], AudioEditConstant.isBigEnding) / 256);
            }
            return byteArray2;
        }
        return sourceByteArray;
    }

    public static byte[] convertChannelNumber(int sourceChannelCount, int outputChannelCount, int byteNumber, byte[] sourceByteArray) {
        if (sourceChannelCount == outputChannelCount) {
            return sourceByteArray;
        }
        if (byteNumber != 1 && byteNumber != 2) {
            return sourceByteArray;
        }
        int sourceByteArrayLength = sourceByteArray.length;
        if (sourceChannelCount == 1) {
            if (outputChannelCount == 2) {
                byte[] byteArray = new byte[sourceByteArrayLength * 2];
                if (byteNumber == 1) {
                    for (int index = 0; index < sourceByteArrayLength; index++) {
                        byte firstByte = sourceByteArray[index];
                        byteArray[index * 2] = firstByte;
                        byteArray[(index * 2) + 1] = firstByte;
                    }
                } else if (byteNumber == 2) {
                    for (int index2 = 0; index2 < sourceByteArrayLength; index2 += 2) {
                        byte firstByte2 = sourceByteArray[index2];
                        byte secondByte = sourceByteArray[index2 + 1];
                        byteArray[index2 * 2] = firstByte2;
                        byteArray[(index2 * 2) + 1] = secondByte;
                        byteArray[(index2 * 2) + 2] = firstByte2;
                        byteArray[(index2 * 2) + 3] = secondByte;
                    }
                }
                return byteArray;
            }
        } else if (sourceChannelCount == 2 && outputChannelCount == 1) {
            int outputByteArrayLength = sourceByteArrayLength / 2;
            byte[] byteArray2 = new byte[outputByteArrayLength];
            if (byteNumber == 1) {
                for (int index3 = 0; index3 < outputByteArrayLength; index3 += 2) {
                    short averageNumber = (short) (sourceByteArray[index3 * 2] + sourceByteArray[(index3 * 2) + 1]);
                    byteArray2[index3] = (byte) (averageNumber >> 1);
                }
            } else if (byteNumber == 2) {
                for (int index4 = 0; index4 < outputByteArrayLength; index4 += 2) {
                    byte[] resultByte = AudioBitUtils.AverageShortByteArray(sourceByteArray[index4 * 2], sourceByteArray[(index4 * 2) + 1], sourceByteArray[(index4 * 2) + 2], sourceByteArray[(index4 * 2) + 3], AudioEditConstant.isBigEnding);
                    byteArray2[index4] = resultByte[0];
                    byteArray2[index4 + 1] = resultByte[1];
                }
            }
            return byteArray2;
        }
        return sourceByteArray;
    }

    private void notifyProgress(final DecodeOperateInterface decodeOperateInterface, final int progress) {
        ApplicationLoader.applicationHandler.post(new Runnable() { // from class: im.uwrkaxlmjj.ui.utils.translate.DecodeEngine.1
            @Override // java.lang.Runnable
            public void run() {
                DecodeOperateInterface decodeOperateInterface2 = decodeOperateInterface;
                if (decodeOperateInterface2 != null) {
                    decodeOperateInterface2.updateDecodeProgress(progress);
                }
            }
        });
    }
}
