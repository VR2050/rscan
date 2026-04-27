package com.google.android.exoplayer2.source.hls;

import android.net.Uri;
import android.text.TextUtils;
import android.util.Pair;
import com.google.android.exoplayer2.Format;
import com.google.android.exoplayer2.drm.DrmInitData;
import com.google.android.exoplayer2.extractor.Extractor;
import com.google.android.exoplayer2.extractor.ExtractorInput;
import com.google.android.exoplayer2.extractor.mp3.Mp3Extractor;
import com.google.android.exoplayer2.extractor.mp4.FragmentedMp4Extractor;
import com.google.android.exoplayer2.extractor.ts.Ac3Extractor;
import com.google.android.exoplayer2.extractor.ts.AdtsExtractor;
import com.google.android.exoplayer2.extractor.ts.DefaultTsPayloadReaderFactory;
import com.google.android.exoplayer2.extractor.ts.TsExtractor;
import com.google.android.exoplayer2.util.MimeTypes;
import com.google.android.exoplayer2.util.TimestampAdjuster;
import java.io.EOFException;
import java.io.IOException;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/* JADX INFO: loaded from: classes2.dex */
public final class DefaultHlsExtractorFactory implements HlsExtractorFactory {
    public static final String AAC_FILE_EXTENSION = ".aac";
    public static final String AC3_FILE_EXTENSION = ".ac3";
    public static final String CMF_FILE_EXTENSION_PREFIX = ".cmf";
    public static final String EC3_FILE_EXTENSION = ".ec3";
    public static final String M4_FILE_EXTENSION_PREFIX = ".m4";
    public static final String MP3_FILE_EXTENSION = ".mp3";
    public static final String MP4_FILE_EXTENSION = ".mp4";
    public static final String MP4_FILE_EXTENSION_PREFIX = ".mp4";
    public static final String VTT_FILE_EXTENSION = ".vtt";
    public static final String WEBVTT_FILE_EXTENSION = ".webvtt";
    private final int payloadReaderFactoryFlags;

    public DefaultHlsExtractorFactory() {
        this(0);
    }

    public DefaultHlsExtractorFactory(int payloadReaderFactoryFlags) {
        this.payloadReaderFactoryFlags = payloadReaderFactoryFlags;
    }

    @Override // com.google.android.exoplayer2.source.hls.HlsExtractorFactory
    public Pair<Extractor, Boolean> createExtractor(Extractor previousExtractor, Uri uri, Format format, List<Format> muxedCaptionFormats, DrmInitData drmInitData, TimestampAdjuster timestampAdjuster, Map<String, List<String>> responseHeaders, ExtractorInput extractorInput) throws InterruptedException, IOException {
        if (previousExtractor != null) {
            if ((previousExtractor instanceof TsExtractor) || (previousExtractor instanceof FragmentedMp4Extractor)) {
                return buildResult(previousExtractor);
            }
            if (previousExtractor instanceof WebvttExtractor) {
                return buildResult(new WebvttExtractor(format.language, timestampAdjuster));
            }
            if (previousExtractor instanceof AdtsExtractor) {
                return buildResult(new AdtsExtractor());
            }
            if (previousExtractor instanceof Ac3Extractor) {
                return buildResult(new Ac3Extractor());
            }
            if (previousExtractor instanceof Mp3Extractor) {
                return buildResult(new Mp3Extractor());
            }
            throw new IllegalArgumentException("Unexpected previousExtractor type: " + previousExtractor.getClass().getSimpleName());
        }
        Extractor extractorByFileExtension = createExtractorByFileExtension(uri, format, muxedCaptionFormats, drmInitData, timestampAdjuster);
        extractorInput.resetPeekPosition();
        if (sniffQuietly(extractorByFileExtension, extractorInput)) {
            return buildResult(extractorByFileExtension);
        }
        if (!(extractorByFileExtension instanceof WebvttExtractor)) {
            WebvttExtractor webvttExtractor = new WebvttExtractor(format.language, timestampAdjuster);
            if (sniffQuietly(webvttExtractor, extractorInput)) {
                return buildResult(webvttExtractor);
            }
        }
        if (!(extractorByFileExtension instanceof AdtsExtractor)) {
            AdtsExtractor adtsExtractor = new AdtsExtractor();
            if (sniffQuietly(adtsExtractor, extractorInput)) {
                return buildResult(adtsExtractor);
            }
        }
        if (!(extractorByFileExtension instanceof Ac3Extractor)) {
            Ac3Extractor ac3Extractor = new Ac3Extractor();
            if (sniffQuietly(ac3Extractor, extractorInput)) {
                return buildResult(ac3Extractor);
            }
        }
        if (!(extractorByFileExtension instanceof Mp3Extractor)) {
            Mp3Extractor mp3Extractor = new Mp3Extractor(0, 0L);
            if (sniffQuietly(mp3Extractor, extractorInput)) {
                return buildResult(mp3Extractor);
            }
        }
        if (!(extractorByFileExtension instanceof FragmentedMp4Extractor)) {
            FragmentedMp4Extractor fragmentedMp4Extractor = new FragmentedMp4Extractor(0, timestampAdjuster, null, drmInitData, muxedCaptionFormats != null ? muxedCaptionFormats : Collections.emptyList());
            if (sniffQuietly(fragmentedMp4Extractor, extractorInput)) {
                return buildResult(fragmentedMp4Extractor);
            }
        }
        if (!(extractorByFileExtension instanceof TsExtractor)) {
            TsExtractor tsExtractor = createTsExtractor(this.payloadReaderFactoryFlags, format, muxedCaptionFormats, timestampAdjuster);
            if (sniffQuietly(tsExtractor, extractorInput)) {
                return buildResult(tsExtractor);
            }
        }
        return buildResult(extractorByFileExtension);
    }

    private Extractor createExtractorByFileExtension(Uri uri, Format format, List<Format> muxedCaptionFormats, DrmInitData drmInitData, TimestampAdjuster timestampAdjuster) {
        String lastPathSegment = uri.getLastPathSegment();
        if (lastPathSegment == null) {
            lastPathSegment = "";
        }
        if (MimeTypes.TEXT_VTT.equals(format.sampleMimeType) || lastPathSegment.endsWith(WEBVTT_FILE_EXTENSION) || lastPathSegment.endsWith(VTT_FILE_EXTENSION)) {
            return new WebvttExtractor(format.language, timestampAdjuster);
        }
        if (lastPathSegment.endsWith(AAC_FILE_EXTENSION)) {
            return new AdtsExtractor();
        }
        if (lastPathSegment.endsWith(AC3_FILE_EXTENSION) || lastPathSegment.endsWith(EC3_FILE_EXTENSION)) {
            return new Ac3Extractor();
        }
        if (lastPathSegment.endsWith(MP3_FILE_EXTENSION)) {
            return new Mp3Extractor(0, 0L);
        }
        if (lastPathSegment.endsWith(".mp4") || lastPathSegment.startsWith(M4_FILE_EXTENSION_PREFIX, lastPathSegment.length() - 4) || lastPathSegment.startsWith(".mp4", lastPathSegment.length() - 5) || lastPathSegment.startsWith(CMF_FILE_EXTENSION_PREFIX, lastPathSegment.length() - 5)) {
            return new FragmentedMp4Extractor(0, timestampAdjuster, null, drmInitData, muxedCaptionFormats != null ? muxedCaptionFormats : Collections.emptyList());
        }
        return createTsExtractor(this.payloadReaderFactoryFlags, format, muxedCaptionFormats, timestampAdjuster);
    }

    private static TsExtractor createTsExtractor(int userProvidedPayloadReaderFactoryFlags, Format format, List<Format> muxedCaptionFormats, TimestampAdjuster timestampAdjuster) {
        int payloadReaderFactoryFlags = userProvidedPayloadReaderFactoryFlags | 16;
        if (muxedCaptionFormats != null) {
            payloadReaderFactoryFlags |= 32;
        } else {
            muxedCaptionFormats = Collections.singletonList(Format.createTextSampleFormat(null, MimeTypes.APPLICATION_CEA608, 0, null));
        }
        String codecs = format.codecs;
        if (!TextUtils.isEmpty(codecs)) {
            if (!MimeTypes.AUDIO_AAC.equals(MimeTypes.getAudioMediaMimeType(codecs))) {
                payloadReaderFactoryFlags |= 2;
            }
            if (!"video/avc".equals(MimeTypes.getVideoMediaMimeType(codecs))) {
                payloadReaderFactoryFlags |= 4;
            }
        }
        return new TsExtractor(2, timestampAdjuster, new DefaultTsPayloadReaderFactory(payloadReaderFactoryFlags, muxedCaptionFormats));
    }

    private static Pair<Extractor, Boolean> buildResult(Extractor extractor) {
        return new Pair<>(extractor, Boolean.valueOf((extractor instanceof AdtsExtractor) || (extractor instanceof Ac3Extractor) || (extractor instanceof Mp3Extractor)));
    }

    private static boolean sniffQuietly(Extractor extractor, ExtractorInput input) throws InterruptedException, IOException {
        boolean result = false;
        try {
            result = extractor.sniff(input);
        } catch (EOFException e) {
        } catch (Throwable th) {
            input.resetPeekPosition();
            throw th;
        }
        input.resetPeekPosition();
        return result;
    }
}
