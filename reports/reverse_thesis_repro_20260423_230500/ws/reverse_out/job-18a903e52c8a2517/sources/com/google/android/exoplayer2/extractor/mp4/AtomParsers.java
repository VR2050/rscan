package com.google.android.exoplayer2.extractor.mp4;

import android.util.Pair;
import com.coremedia.iso.boxes.MetaBox;
import com.google.android.exoplayer2.C;
import com.google.android.exoplayer2.Format;
import com.google.android.exoplayer2.ParserException;
import com.google.android.exoplayer2.audio.Ac3Util;
import com.google.android.exoplayer2.drm.DrmInitData;
import com.google.android.exoplayer2.extractor.mp4.Atom;
import com.google.android.exoplayer2.extractor.ts.PsExtractor;
import com.google.android.exoplayer2.metadata.Metadata;
import com.google.android.exoplayer2.util.Assertions;
import com.google.android.exoplayer2.util.CodecSpecificDataUtil;
import com.google.android.exoplayer2.util.Log;
import com.google.android.exoplayer2.util.MimeTypes;
import com.google.android.exoplayer2.util.ParsableByteArray;
import com.google.android.exoplayer2.util.Util;
import com.google.android.exoplayer2.video.AvcConfig;
import com.google.android.exoplayer2.video.HevcConfig;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import org.webrtc.mozi.JavaScreenCapturer;

/* JADX INFO: loaded from: classes2.dex */
final class AtomParsers {
    private static final int MAX_GAPLESS_TRIM_SIZE_SAMPLES = 3;
    private static final String TAG = "AtomParsers";
    private static final int TYPE_vide = Util.getIntegerCodeForString("vide");
    private static final int TYPE_soun = Util.getIntegerCodeForString("soun");
    private static final int TYPE_text = Util.getIntegerCodeForString("text");
    private static final int TYPE_sbtl = Util.getIntegerCodeForString("sbtl");
    private static final int TYPE_subt = Util.getIntegerCodeForString("subt");
    private static final int TYPE_clcp = Util.getIntegerCodeForString("clcp");
    private static final int TYPE_meta = Util.getIntegerCodeForString(MetaBox.TYPE);
    private static final int TYPE_mdta = Util.getIntegerCodeForString("mdta");
    private static final byte[] opusMagic = Util.getUtf8Bytes("OpusHead");

    private interface SampleSizeBox {
        int getSampleCount();

        boolean isFixedSampleSize();

        int readNextSampleSize();
    }

    public static Track parseTrak(Atom.ContainerAtom trak, Atom.LeafAtom mvhd, long duration, DrmInitData drmInitData, boolean ignoreEditLists, boolean isQuickTime) throws ParserException {
        long duration2;
        long durationUs;
        long[] editListDurations;
        long[] editListMediaTimes;
        Atom.ContainerAtom mdia = trak.getContainerAtomOfType(Atom.TYPE_mdia);
        int trackType = getTrackTypeForHdlr(parseHdlr(mdia.getLeafAtomOfType(Atom.TYPE_hdlr).data));
        if (trackType != -1) {
            TkhdData tkhdData = parseTkhd(trak.getLeafAtomOfType(Atom.TYPE_tkhd).data);
            if (duration != C.TIME_UNSET) {
                duration2 = duration;
            } else {
                duration2 = tkhdData.duration;
            }
            long movieTimescale = parseMvhd(mvhd.data);
            if (duration2 == C.TIME_UNSET) {
                durationUs = -9223372036854775807L;
            } else {
                durationUs = Util.scaleLargeTimestamp(duration2, 1000000L, movieTimescale);
            }
            Atom.ContainerAtom stbl = mdia.getContainerAtomOfType(Atom.TYPE_minf).getContainerAtomOfType(Atom.TYPE_stbl);
            Pair<Long, String> mdhdData = parseMdhd(mdia.getLeafAtomOfType(Atom.TYPE_mdhd).data);
            StsdData stsdData = parseStsd(stbl.getLeafAtomOfType(Atom.TYPE_stsd).data, tkhdData.id, tkhdData.rotationDegrees, (String) mdhdData.second, drmInitData, isQuickTime);
            if (!ignoreEditLists) {
                Pair<long[], long[]> edtsData = parseEdts(trak.getContainerAtomOfType(Atom.TYPE_edts));
                long[] editListDurations2 = (long[]) edtsData.first;
                long[] editListMediaTimes2 = (long[]) edtsData.second;
                editListDurations = editListDurations2;
                editListMediaTimes = editListMediaTimes2;
            } else {
                editListDurations = null;
                editListMediaTimes = null;
            }
            if (stsdData.format == null) {
                return null;
            }
            return new Track(tkhdData.id, trackType, ((Long) mdhdData.first).longValue(), movieTimescale, durationUs, stsdData.format, stsdData.requiredSampleTransformation, stsdData.trackEncryptionBoxes, stsdData.nalUnitLengthFieldLength, editListDurations, editListMediaTimes);
        }
        return null;
    }

    /* JADX WARN: Removed duplicated region for block: B:101:0x028e  */
    /* JADX WARN: Removed duplicated region for block: B:46:0x00fe  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static com.google.android.exoplayer2.extractor.mp4.TrackSampleTable parseStbl(com.google.android.exoplayer2.extractor.mp4.Track r72, com.google.android.exoplayer2.extractor.mp4.Atom.ContainerAtom r73, com.google.android.exoplayer2.extractor.GaplessInfoHolder r74) throws com.google.android.exoplayer2.ParserException {
        /*
            Method dump skipped, instruction units count: 1537
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.exoplayer2.extractor.mp4.AtomParsers.parseStbl(com.google.android.exoplayer2.extractor.mp4.Track, com.google.android.exoplayer2.extractor.mp4.Atom$ContainerAtom, com.google.android.exoplayer2.extractor.GaplessInfoHolder):com.google.android.exoplayer2.extractor.mp4.TrackSampleTable");
    }

    public static Metadata parseUdta(Atom.LeafAtom udtaAtom, boolean isQuickTime) {
        if (isQuickTime) {
            return null;
        }
        ParsableByteArray udtaData = udtaAtom.data;
        udtaData.setPosition(8);
        while (udtaData.bytesLeft() >= 8) {
            int atomPosition = udtaData.getPosition();
            int atomSize = udtaData.readInt();
            int atomType = udtaData.readInt();
            if (atomType == Atom.TYPE_meta) {
                udtaData.setPosition(atomPosition);
                return parseUdtaMeta(udtaData, atomPosition + atomSize);
            }
            udtaData.setPosition(atomPosition + atomSize);
        }
        return null;
    }

    public static Metadata parseMdtaFromMeta(Atom.ContainerAtom meta) {
        Atom.LeafAtom hdlrAtom = meta.getLeafAtomOfType(Atom.TYPE_hdlr);
        Atom.LeafAtom keysAtom = meta.getLeafAtomOfType(Atom.TYPE_keys);
        Atom.LeafAtom ilstAtom = meta.getLeafAtomOfType(Atom.TYPE_ilst);
        if (hdlrAtom == null || keysAtom == null || ilstAtom == null || parseHdlr(hdlrAtom.data) != TYPE_mdta) {
            return null;
        }
        ParsableByteArray keys = keysAtom.data;
        keys.setPosition(12);
        int entryCount = keys.readInt();
        String[] keyNames = new String[entryCount];
        for (int i = 0; i < entryCount; i++) {
            int entrySize = keys.readInt();
            keys.skipBytes(4);
            int keySize = entrySize - 8;
            keyNames[i] = keys.readString(keySize);
        }
        ParsableByteArray ilst = ilstAtom.data;
        ilst.setPosition(8);
        ArrayList<Metadata.Entry> entries = new ArrayList<>();
        while (ilst.bytesLeft() > 8) {
            int atomPosition = ilst.getPosition();
            int atomSize = ilst.readInt();
            int keyIndex = ilst.readInt() - 1;
            if (keyIndex >= 0 && keyIndex < keyNames.length) {
                String key = keyNames[keyIndex];
                Metadata.Entry entry = MetadataUtil.parseMdtaMetadataEntryFromIlst(ilst, atomPosition + atomSize, key);
                if (entry != null) {
                    entries.add(entry);
                }
            } else {
                Log.w(TAG, "Skipped metadata with unknown key index: " + keyIndex);
            }
            ilst.setPosition(atomPosition + atomSize);
        }
        if (entries.isEmpty()) {
            return null;
        }
        return new Metadata(entries);
    }

    private static Metadata parseUdtaMeta(ParsableByteArray meta, int limit) {
        meta.skipBytes(12);
        while (meta.getPosition() < limit) {
            int atomPosition = meta.getPosition();
            int atomSize = meta.readInt();
            int atomType = meta.readInt();
            if (atomType == Atom.TYPE_ilst) {
                meta.setPosition(atomPosition);
                return parseIlst(meta, atomPosition + atomSize);
            }
            meta.setPosition(atomPosition + atomSize);
        }
        return null;
    }

    private static Metadata parseIlst(ParsableByteArray ilst, int limit) {
        ilst.skipBytes(8);
        ArrayList<Metadata.Entry> entries = new ArrayList<>();
        while (ilst.getPosition() < limit) {
            Metadata.Entry entry = MetadataUtil.parseIlstElement(ilst);
            if (entry != null) {
                entries.add(entry);
            }
        }
        if (entries.isEmpty()) {
            return null;
        }
        return new Metadata(entries);
    }

    private static long parseMvhd(ParsableByteArray mvhd) {
        mvhd.setPosition(8);
        int fullAtom = mvhd.readInt();
        int version = Atom.parseFullAtomVersion(fullAtom);
        mvhd.skipBytes(version != 0 ? 16 : 8);
        return mvhd.readUnsignedInt();
    }

    private static TkhdData parseTkhd(ParsableByteArray tkhd) {
        long duration;
        int rotationDegrees;
        tkhd.setPosition(8);
        int fullAtom = tkhd.readInt();
        int version = Atom.parseFullAtomVersion(fullAtom);
        tkhd.skipBytes(version == 0 ? 8 : 16);
        int trackId = tkhd.readInt();
        tkhd.skipBytes(4);
        boolean durationUnknown = true;
        int durationPosition = tkhd.getPosition();
        int durationByteCount = version == 0 ? 4 : 8;
        int i = 0;
        while (true) {
            if (i >= durationByteCount) {
                break;
            }
            if (tkhd.data[durationPosition + i] == -1) {
                i++;
            } else {
                durationUnknown = false;
                break;
            }
        }
        if (durationUnknown) {
            tkhd.skipBytes(durationByteCount);
            duration = C.TIME_UNSET;
        } else {
            duration = version == 0 ? tkhd.readUnsignedInt() : tkhd.readUnsignedLongToLong();
            if (duration == 0) {
                duration = C.TIME_UNSET;
            }
        }
        tkhd.skipBytes(16);
        int a00 = tkhd.readInt();
        int a01 = tkhd.readInt();
        tkhd.skipBytes(4);
        int a10 = tkhd.readInt();
        int a11 = tkhd.readInt();
        if (a00 == 0 && a01 == 65536 && a10 == (-65536) && a11 == 0) {
            rotationDegrees = 90;
        } else if (a00 == 0 && a01 == (-65536) && a10 == 65536 && a11 == 0) {
            rotationDegrees = JavaScreenCapturer.DEGREE_270;
        } else {
            int rotationDegrees2 = -65536;
            if (a00 == rotationDegrees2 && a01 == 0 && a10 == 0 && a11 == (-65536)) {
                rotationDegrees = JavaScreenCapturer.DEGREE_180;
            } else {
                rotationDegrees = 0;
            }
        }
        return new TkhdData(trackId, duration, rotationDegrees);
    }

    private static int parseHdlr(ParsableByteArray hdlr) {
        hdlr.setPosition(16);
        return hdlr.readInt();
    }

    private static int getTrackTypeForHdlr(int hdlr) {
        if (hdlr == TYPE_soun) {
            return 1;
        }
        if (hdlr == TYPE_vide) {
            return 2;
        }
        if (hdlr == TYPE_text || hdlr == TYPE_sbtl || hdlr == TYPE_subt || hdlr == TYPE_clcp) {
            return 3;
        }
        if (hdlr == TYPE_meta) {
            return 4;
        }
        return -1;
    }

    private static Pair<Long, String> parseMdhd(ParsableByteArray mdhd) {
        mdhd.setPosition(8);
        int fullAtom = mdhd.readInt();
        int version = Atom.parseFullAtomVersion(fullAtom);
        mdhd.skipBytes(version == 0 ? 8 : 16);
        long timescale = mdhd.readUnsignedInt();
        mdhd.skipBytes(version == 0 ? 4 : 8);
        int languageCode = mdhd.readUnsignedShort();
        String language = "" + ((char) (((languageCode >> 10) & 31) + 96)) + ((char) (((languageCode >> 5) & 31) + 96)) + ((char) ((languageCode & 31) + 96));
        return Pair.create(Long.valueOf(timescale), language);
    }

    private static StsdData parseStsd(ParsableByteArray stsd, int trackId, int rotationDegrees, String language, DrmInitData drmInitData, boolean isQuickTime) throws ParserException {
        stsd.setPosition(12);
        int numberOfEntries = stsd.readInt();
        StsdData out = new StsdData(numberOfEntries);
        for (int i = 0; i < numberOfEntries; i++) {
            int childStartPosition = stsd.getPosition();
            int childAtomSize = stsd.readInt();
            Assertions.checkArgument(childAtomSize > 0, "childAtomSize should be positive");
            int childAtomType = stsd.readInt();
            if (childAtomType == Atom.TYPE_avc1 || childAtomType == Atom.TYPE_avc3 || childAtomType == Atom.TYPE_encv || childAtomType == Atom.TYPE_mp4v || childAtomType == Atom.TYPE_hvc1 || childAtomType == Atom.TYPE_hev1 || childAtomType == Atom.TYPE_s263 || childAtomType == Atom.TYPE_vp08 || childAtomType == Atom.TYPE_vp09) {
                int childAtomType2 = childAtomType;
                parseVideoSampleEntry(stsd, childAtomType2, childStartPosition, childAtomSize, trackId, rotationDegrees, drmInitData, out, i);
                stsd.setPosition(childStartPosition + childAtomSize);
            } else {
                if (childAtomType == Atom.TYPE_mp4a || childAtomType == Atom.TYPE_enca || childAtomType == Atom.TYPE_ac_3 || childAtomType == Atom.TYPE_ec_3 || childAtomType == Atom.TYPE_dtsc || childAtomType == Atom.TYPE_dtse || childAtomType == Atom.TYPE_dtsh || childAtomType == Atom.TYPE_dtsl || childAtomType == Atom.TYPE_samr || childAtomType == Atom.TYPE_sawb || childAtomType == Atom.TYPE_lpcm || childAtomType == Atom.TYPE_sowt || childAtomType == Atom.TYPE__mp3 || childAtomType == Atom.TYPE_alac || childAtomType == Atom.TYPE_alaw || childAtomType == Atom.TYPE_ulaw || childAtomType == Atom.TYPE_Opus || childAtomType == Atom.TYPE_fLaC) {
                    parseAudioSampleEntry(stsd, childAtomType, childStartPosition, childAtomSize, trackId, language, isQuickTime, drmInitData, out, i);
                } else if (childAtomType == Atom.TYPE_TTML || childAtomType == Atom.TYPE_tx3g || childAtomType == Atom.TYPE_wvtt || childAtomType == Atom.TYPE_stpp || childAtomType == Atom.TYPE_c608) {
                    parseTextSampleEntry(stsd, childAtomType, childStartPosition, childAtomSize, trackId, language, out);
                } else if (childAtomType == Atom.TYPE_camm) {
                    out.format = Format.createSampleFormat(Integer.toString(trackId), MimeTypes.APPLICATION_CAMERA_MOTION, null, -1, null);
                }
                stsd.setPosition(childStartPosition + childAtomSize);
            }
        }
        return out;
    }

    private static void parseTextSampleEntry(ParsableByteArray parent, int atomType, int position, int atomSize, int trackId, String language, StsdData out) throws ParserException {
        String mimeType;
        parent.setPosition(position + 8 + 8);
        List<byte[]> initializationData = null;
        long subsampleOffsetUs = Long.MAX_VALUE;
        if (atomType == Atom.TYPE_TTML) {
            mimeType = MimeTypes.APPLICATION_TTML;
        } else if (atomType == Atom.TYPE_tx3g) {
            mimeType = MimeTypes.APPLICATION_TX3G;
            int sampleDescriptionLength = (atomSize - 8) - 8;
            byte[] sampleDescriptionData = new byte[sampleDescriptionLength];
            parent.readBytes(sampleDescriptionData, 0, sampleDescriptionLength);
            initializationData = Collections.singletonList(sampleDescriptionData);
        } else if (atomType == Atom.TYPE_wvtt) {
            mimeType = MimeTypes.APPLICATION_MP4VTT;
        } else if (atomType == Atom.TYPE_stpp) {
            mimeType = MimeTypes.APPLICATION_TTML;
            subsampleOffsetUs = 0;
        } else if (atomType == Atom.TYPE_c608) {
            mimeType = MimeTypes.APPLICATION_MP4CEA608;
            out.requiredSampleTransformation = 1;
        } else {
            throw new IllegalStateException();
        }
        out.format = Format.createTextSampleFormat(Integer.toString(trackId), mimeType, null, -1, 0, language, -1, null, subsampleOffsetUs, initializationData);
    }

    private static void parseVideoSampleEntry(ParsableByteArray parent, int atomType, int position, int size, int trackId, int rotationDegrees, DrmInitData drmInitData, StsdData out, int entryIndex) throws ParserException {
        DrmInitData drmInitData2;
        int atomType2;
        DrmInitData drmInitData3 = drmInitData;
        parent.setPosition(position + 8 + 8);
        parent.skipBytes(16);
        int width = parent.readUnsignedShort();
        int height = parent.readUnsignedShort();
        parent.skipBytes(50);
        int childPosition = parent.getPosition();
        int atomType3 = atomType;
        if (atomType3 != Atom.TYPE_encv) {
            drmInitData2 = drmInitData3;
            atomType2 = atomType3;
        } else {
            Pair<Integer, TrackEncryptionBox> sampleEntryEncryptionData = parseSampleEntryEncryptionData(parent, position, size);
            if (sampleEntryEncryptionData != null) {
                atomType3 = ((Integer) sampleEntryEncryptionData.first).intValue();
                drmInitData3 = drmInitData3 == null ? null : drmInitData3.copyWithSchemeType(((TrackEncryptionBox) sampleEntryEncryptionData.second).schemeType);
                out.trackEncryptionBoxes[entryIndex] = (TrackEncryptionBox) sampleEntryEncryptionData.second;
            }
            parent.setPosition(childPosition);
            drmInitData2 = drmInitData3;
            atomType2 = atomType3;
        }
        boolean pixelWidthHeightRatioFromPasp = false;
        float pixelWidthHeightRatio = 1.0f;
        int childPosition2 = childPosition;
        List<byte[]> initializationData = null;
        String mimeType = null;
        byte[] projectionData = null;
        int stereoMode = -1;
        while (childPosition2 - position < size) {
            parent.setPosition(childPosition2);
            int childStartPosition = parent.getPosition();
            int childAtomSize = parent.readInt();
            if (childAtomSize == 0 && parent.getPosition() - position == size) {
                break;
            }
            Assertions.checkArgument(childAtomSize > 0, "childAtomSize should be positive");
            int childAtomType = parent.readInt();
            if (childAtomType == Atom.TYPE_avcC) {
                Assertions.checkState(mimeType == null);
                parent.setPosition(childStartPosition + 8);
                AvcConfig avcConfig = AvcConfig.parse(parent);
                List<byte[]> initializationData2 = avcConfig.initializationData;
                out.nalUnitLengthFieldLength = avcConfig.nalUnitLengthFieldLength;
                if (!pixelWidthHeightRatioFromPasp) {
                    pixelWidthHeightRatio = avcConfig.pixelWidthAspectRatio;
                }
                mimeType = "video/avc";
                initializationData = initializationData2;
            } else if (childAtomType == Atom.TYPE_hvcC) {
                Assertions.checkState(mimeType == null);
                parent.setPosition(childStartPosition + 8);
                HevcConfig hevcConfig = HevcConfig.parse(parent);
                List<byte[]> initializationData3 = hevcConfig.initializationData;
                out.nalUnitLengthFieldLength = hevcConfig.nalUnitLengthFieldLength;
                mimeType = MimeTypes.VIDEO_H265;
                initializationData = initializationData3;
            } else if (childAtomType == Atom.TYPE_vpcC) {
                Assertions.checkState(mimeType == null);
                mimeType = atomType2 == Atom.TYPE_vp08 ? MimeTypes.VIDEO_VP8 : MimeTypes.VIDEO_VP9;
            } else if (childAtomType == Atom.TYPE_d263) {
                Assertions.checkState(mimeType == null);
                mimeType = MimeTypes.VIDEO_H263;
            } else if (childAtomType == Atom.TYPE_esds) {
                Assertions.checkState(mimeType == null);
                Pair<String, byte[]> mimeTypeAndInitializationData = parseEsdsFromParent(parent, childStartPosition);
                String mimeType2 = (String) mimeTypeAndInitializationData.first;
                List<byte[]> initializationData4 = Collections.singletonList(mimeTypeAndInitializationData.second);
                initializationData = initializationData4;
                mimeType = mimeType2;
            } else if (childAtomType == Atom.TYPE_pasp) {
                float pixelWidthHeightRatio2 = parsePaspFromParent(parent, childStartPosition);
                pixelWidthHeightRatio = pixelWidthHeightRatio2;
                pixelWidthHeightRatioFromPasp = true;
            } else if (childAtomType == Atom.TYPE_sv3d) {
                projectionData = parseProjFromParent(parent, childStartPosition, childAtomSize);
            } else if (childAtomType == Atom.TYPE_st3d) {
                int version = parent.readUnsignedByte();
                parent.skipBytes(3);
                if (version == 0) {
                    int layout = parent.readUnsignedByte();
                    if (layout == 0) {
                        stereoMode = 0;
                    } else if (layout == 1) {
                        stereoMode = 1;
                    } else if (layout != 2) {
                        if (layout == 3) {
                            stereoMode = 3;
                        }
                    } else {
                        stereoMode = 2;
                    }
                }
            }
            childPosition2 += childAtomSize;
        }
        if (mimeType == null) {
            return;
        }
        out.format = Format.createVideoSampleFormat(Integer.toString(trackId), mimeType, null, -1, -1, width, height, -1.0f, initializationData, rotationDegrees, pixelWidthHeightRatio, projectionData, stereoMode, null, drmInitData2);
    }

    private static Pair<long[], long[]> parseEdts(Atom.ContainerAtom edtsAtom) {
        Atom.LeafAtom elst;
        if (edtsAtom == null || (elst = edtsAtom.getLeafAtomOfType(Atom.TYPE_elst)) == null) {
            return Pair.create(null, null);
        }
        ParsableByteArray elstData = elst.data;
        elstData.setPosition(8);
        int fullAtom = elstData.readInt();
        int version = Atom.parseFullAtomVersion(fullAtom);
        int entryCount = elstData.readUnsignedIntToInt();
        long[] editListDurations = new long[entryCount];
        long[] editListMediaTimes = new long[entryCount];
        for (int i = 0; i < entryCount; i++) {
            editListDurations[i] = version == 1 ? elstData.readUnsignedLongToLong() : elstData.readUnsignedInt();
            editListMediaTimes[i] = version == 1 ? elstData.readLong() : elstData.readInt();
            int mediaRateInteger = elstData.readShort();
            if (mediaRateInteger != 1) {
                throw new IllegalArgumentException("Unsupported media rate.");
            }
            elstData.skipBytes(2);
        }
        return Pair.create(editListDurations, editListMediaTimes);
    }

    private static float parsePaspFromParent(ParsableByteArray parent, int position) {
        parent.setPosition(position + 8);
        int hSpacing = parent.readUnsignedIntToInt();
        int vSpacing = parent.readUnsignedIntToInt();
        return hSpacing / vSpacing;
    }

    private static void parseAudioSampleEntry(ParsableByteArray parent, int atomType, int position, int size, int trackId, String language, boolean isQuickTime, DrmInitData drmInitData, StsdData out, int entryIndex) throws ParserException {
        int quickTimeSoundDescriptionVersion;
        int channelCount;
        int channelCount2;
        DrmInitData drmInitData2;
        int atomType2;
        String mimeType;
        DrmInitData drmInitData3;
        int atomType3;
        int childAtomType;
        int quickTimeSoundDescriptionVersion2;
        int quickTimeSoundDescriptionVersion3;
        String mimeType2;
        DrmInitData drmInitData4 = drmInitData;
        parent.setPosition(position + 8 + 8);
        if (isQuickTime) {
            int quickTimeSoundDescriptionVersion4 = parent.readUnsignedShort();
            parent.skipBytes(6);
            quickTimeSoundDescriptionVersion = quickTimeSoundDescriptionVersion4;
        } else {
            parent.skipBytes(8);
            quickTimeSoundDescriptionVersion = 0;
        }
        if (quickTimeSoundDescriptionVersion == 0 || quickTimeSoundDescriptionVersion == 1) {
            int channelCount3 = parent.readUnsignedShort();
            parent.skipBytes(6);
            int sampleRate = parent.readUnsignedFixedPoint1616();
            if (quickTimeSoundDescriptionVersion == 1) {
                parent.skipBytes(16);
            }
            channelCount = channelCount3;
            channelCount2 = sampleRate;
        } else if (quickTimeSoundDescriptionVersion == 2) {
            parent.skipBytes(16);
            channelCount2 = (int) Math.round(parent.readDouble());
            channelCount = parent.readUnsignedIntToInt();
            parent.skipBytes(20);
        } else {
            return;
        }
        int childPosition = parent.getPosition();
        int atomType4 = atomType;
        if (atomType4 != Atom.TYPE_enca) {
            drmInitData2 = drmInitData4;
            atomType2 = atomType4;
        } else {
            Pair<Integer, TrackEncryptionBox> sampleEntryEncryptionData = parseSampleEntryEncryptionData(parent, position, size);
            if (sampleEntryEncryptionData != null) {
                atomType4 = ((Integer) sampleEntryEncryptionData.first).intValue();
                drmInitData4 = drmInitData4 == null ? null : drmInitData4.copyWithSchemeType(((TrackEncryptionBox) sampleEntryEncryptionData.second).schemeType);
                out.trackEncryptionBoxes[entryIndex] = (TrackEncryptionBox) sampleEntryEncryptionData.second;
            }
            parent.setPosition(childPosition);
            drmInitData2 = drmInitData4;
            atomType2 = atomType4;
        }
        String mimeType3 = null;
        if (atomType2 == Atom.TYPE_ac_3) {
            mimeType3 = MimeTypes.AUDIO_AC3;
        } else if (atomType2 == Atom.TYPE_ec_3) {
            mimeType3 = MimeTypes.AUDIO_E_AC3;
        } else if (atomType2 == Atom.TYPE_dtsc) {
            mimeType3 = MimeTypes.AUDIO_DTS;
        } else if (atomType2 == Atom.TYPE_dtsh || atomType2 == Atom.TYPE_dtsl) {
            mimeType3 = MimeTypes.AUDIO_DTS_HD;
        } else if (atomType2 == Atom.TYPE_dtse) {
            mimeType3 = MimeTypes.AUDIO_DTS_EXPRESS;
        } else if (atomType2 == Atom.TYPE_samr) {
            mimeType3 = MimeTypes.AUDIO_AMR_NB;
        } else if (atomType2 == Atom.TYPE_sawb) {
            mimeType3 = MimeTypes.AUDIO_AMR_WB;
        } else if (atomType2 == Atom.TYPE_lpcm || atomType2 == Atom.TYPE_sowt) {
            mimeType3 = MimeTypes.AUDIO_RAW;
        } else if (atomType2 == Atom.TYPE__mp3) {
            mimeType3 = MimeTypes.AUDIO_MPEG;
        } else if (atomType2 == Atom.TYPE_alac) {
            mimeType3 = MimeTypes.AUDIO_ALAC;
        } else if (atomType2 == Atom.TYPE_alaw) {
            mimeType3 = MimeTypes.AUDIO_ALAW;
        } else if (atomType2 == Atom.TYPE_ulaw) {
            mimeType3 = MimeTypes.AUDIO_MLAW;
        } else if (atomType2 == Atom.TYPE_Opus) {
            mimeType3 = MimeTypes.AUDIO_OPUS;
        } else if (atomType2 == Atom.TYPE_fLaC) {
            mimeType3 = MimeTypes.AUDIO_FLAC;
        }
        String mimeType4 = mimeType3;
        int channelCount4 = channelCount;
        int sampleRate2 = channelCount2;
        byte[] initializationData = null;
        int childPosition2 = childPosition;
        while (childPosition2 - position < size) {
            parent.setPosition(childPosition2);
            int childAtomSize = parent.readInt();
            Assertions.checkArgument(childAtomSize > 0, "childAtomSize should be positive");
            int childAtomType2 = parent.readInt();
            if (childAtomType2 == Atom.TYPE_esds) {
                mimeType = mimeType4;
                drmInitData3 = drmInitData2;
                atomType3 = atomType2;
                childAtomType = childAtomType2;
                quickTimeSoundDescriptionVersion2 = quickTimeSoundDescriptionVersion;
                quickTimeSoundDescriptionVersion3 = childPosition2;
            } else if (isQuickTime && childAtomType2 == Atom.TYPE_wave) {
                mimeType = mimeType4;
                drmInitData3 = drmInitData2;
                atomType3 = atomType2;
                childAtomType = childAtomType2;
                quickTimeSoundDescriptionVersion2 = quickTimeSoundDescriptionVersion;
                quickTimeSoundDescriptionVersion3 = childPosition2;
            } else {
                if (childAtomType2 == Atom.TYPE_dac3) {
                    parent.setPosition(childPosition2 + 8);
                    out.format = Ac3Util.parseAc3AnnexFFormat(parent, Integer.toString(trackId), language, drmInitData2);
                    mimeType2 = mimeType4;
                    drmInitData3 = drmInitData2;
                    atomType3 = atomType2;
                    quickTimeSoundDescriptionVersion2 = quickTimeSoundDescriptionVersion;
                    quickTimeSoundDescriptionVersion3 = childPosition2;
                } else if (childAtomType2 == Atom.TYPE_dec3) {
                    parent.setPosition(childPosition2 + 8);
                    out.format = Ac3Util.parseEAc3AnnexFFormat(parent, Integer.toString(trackId), language, drmInitData2);
                    mimeType2 = mimeType4;
                    drmInitData3 = drmInitData2;
                    atomType3 = atomType2;
                    quickTimeSoundDescriptionVersion2 = quickTimeSoundDescriptionVersion;
                    quickTimeSoundDescriptionVersion3 = childPosition2;
                } else if (childAtomType2 == Atom.TYPE_ddts) {
                    mimeType2 = mimeType4;
                    drmInitData3 = drmInitData2;
                    atomType3 = atomType2;
                    quickTimeSoundDescriptionVersion2 = quickTimeSoundDescriptionVersion;
                    out.format = Format.createAudioSampleFormat(Integer.toString(trackId), mimeType4, null, -1, -1, channelCount4, sampleRate2, null, drmInitData3, 0, language);
                    childAtomSize = childAtomSize;
                    quickTimeSoundDescriptionVersion3 = childPosition2;
                } else {
                    int childPosition3 = childPosition2;
                    mimeType2 = mimeType4;
                    drmInitData3 = drmInitData2;
                    atomType3 = atomType2;
                    quickTimeSoundDescriptionVersion2 = quickTimeSoundDescriptionVersion;
                    if (childAtomType2 == Atom.TYPE_alac) {
                        childAtomSize = childAtomSize;
                        byte[] initializationData2 = new byte[childAtomSize];
                        quickTimeSoundDescriptionVersion3 = childPosition3;
                        parent.setPosition(quickTimeSoundDescriptionVersion3);
                        parent.readBytes(initializationData2, 0, childAtomSize);
                        initializationData = initializationData2;
                        mimeType4 = mimeType2;
                    } else {
                        childAtomSize = childAtomSize;
                        quickTimeSoundDescriptionVersion3 = childPosition3;
                        if (childAtomType2 == Atom.TYPE_dOps) {
                            int childAtomBodySize = childAtomSize - 8;
                            byte[] bArr = opusMagic;
                            byte[] initializationData3 = new byte[bArr.length + childAtomBodySize];
                            System.arraycopy(bArr, 0, initializationData3, 0, bArr.length);
                            parent.setPosition(quickTimeSoundDescriptionVersion3 + 8);
                            parent.readBytes(initializationData3, opusMagic.length, childAtomBodySize);
                            initializationData = initializationData3;
                            mimeType4 = mimeType2;
                        } else if (childAtomSize == Atom.TYPE_dfLa) {
                            int childAtomBodySize2 = childAtomSize - 12;
                            byte[] initializationData4 = new byte[childAtomBodySize2];
                            parent.setPosition(quickTimeSoundDescriptionVersion3 + 12);
                            parent.readBytes(initializationData4, 0, childAtomBodySize2);
                            initializationData = initializationData4;
                            mimeType4 = mimeType2;
                        }
                    }
                    childPosition2 = quickTimeSoundDescriptionVersion3 + childAtomSize;
                    drmInitData2 = drmInitData3;
                    atomType2 = atomType3;
                    quickTimeSoundDescriptionVersion = quickTimeSoundDescriptionVersion2;
                }
                mimeType4 = mimeType2;
                childPosition2 = quickTimeSoundDescriptionVersion3 + childAtomSize;
                drmInitData2 = drmInitData3;
                atomType2 = atomType3;
                quickTimeSoundDescriptionVersion = quickTimeSoundDescriptionVersion2;
            }
            int esdsAtomPosition = childAtomType == Atom.TYPE_esds ? quickTimeSoundDescriptionVersion3 : findEsdsPosition(parent, quickTimeSoundDescriptionVersion3, childAtomSize);
            if (esdsAtomPosition == -1) {
                mimeType4 = mimeType;
            } else {
                Pair<String, byte[]> mimeTypeAndInitializationData = parseEsdsFromParent(parent, esdsAtomPosition);
                mimeType4 = (String) mimeTypeAndInitializationData.first;
                initializationData = (byte[]) mimeTypeAndInitializationData.second;
                if (MimeTypes.AUDIO_AAC.equals(mimeType4)) {
                    Pair<Integer, Integer> audioSpecificConfig = CodecSpecificDataUtil.parseAacAudioSpecificConfig(initializationData);
                    sampleRate2 = ((Integer) audioSpecificConfig.first).intValue();
                    channelCount4 = ((Integer) audioSpecificConfig.second).intValue();
                }
            }
            childPosition2 = quickTimeSoundDescriptionVersion3 + childAtomSize;
            drmInitData2 = drmInitData3;
            atomType2 = atomType3;
            quickTimeSoundDescriptionVersion = quickTimeSoundDescriptionVersion2;
        }
        String mimeType5 = mimeType4;
        DrmInitData drmInitData5 = drmInitData2;
        if (out.format == null && mimeType5 != null) {
            int pcmEncoding = MimeTypes.AUDIO_RAW.equals(mimeType5) ? 2 : -1;
            out.format = Format.createAudioSampleFormat(Integer.toString(trackId), mimeType5, null, -1, -1, channelCount4, sampleRate2, pcmEncoding, initializationData == null ? null : Collections.singletonList(initializationData), drmInitData5, 0, language);
        }
    }

    private static int findEsdsPosition(ParsableByteArray parent, int position, int size) {
        int childAtomPosition = parent.getPosition();
        while (childAtomPosition - position < size) {
            parent.setPosition(childAtomPosition);
            int childAtomSize = parent.readInt();
            Assertions.checkArgument(childAtomSize > 0, "childAtomSize should be positive");
            int childType = parent.readInt();
            if (childType == Atom.TYPE_esds) {
                return childAtomPosition;
            }
            childAtomPosition += childAtomSize;
        }
        return -1;
    }

    private static Pair<String, byte[]> parseEsdsFromParent(ParsableByteArray parent, int position) {
        parent.setPosition(position + 8 + 4);
        parent.skipBytes(1);
        parseExpandableClassSize(parent);
        parent.skipBytes(2);
        int flags = parent.readUnsignedByte();
        if ((flags & 128) != 0) {
            parent.skipBytes(2);
        }
        if ((flags & 64) != 0) {
            parent.skipBytes(parent.readUnsignedShort());
        }
        if ((flags & 32) != 0) {
            parent.skipBytes(2);
        }
        parent.skipBytes(1);
        parseExpandableClassSize(parent);
        int objectTypeIndication = parent.readUnsignedByte();
        String mimeType = MimeTypes.getMimeTypeFromMp4ObjectType(objectTypeIndication);
        if (MimeTypes.AUDIO_MPEG.equals(mimeType) || MimeTypes.AUDIO_DTS.equals(mimeType) || MimeTypes.AUDIO_DTS_HD.equals(mimeType)) {
            return Pair.create(mimeType, null);
        }
        parent.skipBytes(12);
        parent.skipBytes(1);
        int initializationDataSize = parseExpandableClassSize(parent);
        byte[] initializationData = new byte[initializationDataSize];
        parent.readBytes(initializationData, 0, initializationDataSize);
        return Pair.create(mimeType, initializationData);
    }

    private static Pair<Integer, TrackEncryptionBox> parseSampleEntryEncryptionData(ParsableByteArray parent, int position, int size) {
        Pair<Integer, TrackEncryptionBox> result;
        int childPosition = parent.getPosition();
        while (childPosition - position < size) {
            parent.setPosition(childPosition);
            int childAtomSize = parent.readInt();
            Assertions.checkArgument(childAtomSize > 0, "childAtomSize should be positive");
            int childAtomType = parent.readInt();
            if (childAtomType == Atom.TYPE_sinf && (result = parseCommonEncryptionSinfFromParent(parent, childPosition, childAtomSize)) != null) {
                return result;
            }
            childPosition += childAtomSize;
        }
        return null;
    }

    static Pair<Integer, TrackEncryptionBox> parseCommonEncryptionSinfFromParent(ParsableByteArray parent, int position, int size) {
        int childPosition = position + 8;
        int schemeInformationBoxPosition = -1;
        int schemeInformationBoxSize = 0;
        String schemeType = null;
        Integer dataFormat = null;
        while (childPosition - position < size) {
            parent.setPosition(childPosition);
            int childAtomSize = parent.readInt();
            int childAtomType = parent.readInt();
            if (childAtomType == Atom.TYPE_frma) {
                dataFormat = Integer.valueOf(parent.readInt());
            } else if (childAtomType == Atom.TYPE_schm) {
                parent.skipBytes(4);
                schemeType = parent.readString(4);
            } else if (childAtomType == Atom.TYPE_schi) {
                schemeInformationBoxPosition = childPosition;
                schemeInformationBoxSize = childAtomSize;
            }
            childPosition += childAtomSize;
        }
        if (C.CENC_TYPE_cenc.equals(schemeType) || C.CENC_TYPE_cbc1.equals(schemeType) || C.CENC_TYPE_cens.equals(schemeType) || C.CENC_TYPE_cbcs.equals(schemeType)) {
            Assertions.checkArgument(dataFormat != null, "frma atom is mandatory");
            Assertions.checkArgument(schemeInformationBoxPosition != -1, "schi atom is mandatory");
            TrackEncryptionBox encryptionBox = parseSchiFromParent(parent, schemeInformationBoxPosition, schemeInformationBoxSize, schemeType);
            Assertions.checkArgument(encryptionBox != null, "tenc atom is mandatory");
            return Pair.create(dataFormat, encryptionBox);
        }
        return null;
    }

    private static TrackEncryptionBox parseSchiFromParent(ParsableByteArray parent, int position, int size, String schemeType) {
        byte[] constantIv;
        int childPosition = position + 8;
        while (childPosition - position < size) {
            parent.setPosition(childPosition);
            int childAtomSize = parent.readInt();
            int childAtomType = parent.readInt();
            if (childAtomType == Atom.TYPE_tenc) {
                int fullAtom = parent.readInt();
                int version = Atom.parseFullAtomVersion(fullAtom);
                parent.skipBytes(1);
                int defaultCryptByteBlock = 0;
                int defaultSkipByteBlock = 0;
                if (version == 0) {
                    parent.skipBytes(1);
                } else {
                    int patternByte = parent.readUnsignedByte();
                    defaultCryptByteBlock = (patternByte & PsExtractor.VIDEO_STREAM_MASK) >> 4;
                    defaultSkipByteBlock = patternByte & 15;
                }
                boolean defaultIsProtected = parent.readUnsignedByte() == 1;
                int defaultPerSampleIvSize = parent.readUnsignedByte();
                byte[] defaultKeyId = new byte[16];
                parent.readBytes(defaultKeyId, 0, defaultKeyId.length);
                if (defaultIsProtected && defaultPerSampleIvSize == 0) {
                    int constantIvSize = parent.readUnsignedByte();
                    byte[] constantIv2 = new byte[constantIvSize];
                    parent.readBytes(constantIv2, 0, constantIvSize);
                    constantIv = constantIv2;
                } else {
                    constantIv = null;
                }
                return new TrackEncryptionBox(defaultIsProtected, schemeType, defaultPerSampleIvSize, defaultKeyId, defaultCryptByteBlock, defaultSkipByteBlock, constantIv);
            }
            childPosition += childAtomSize;
        }
        return null;
    }

    private static byte[] parseProjFromParent(ParsableByteArray parent, int position, int size) {
        int childPosition = position + 8;
        while (childPosition - position < size) {
            parent.setPosition(childPosition);
            int childAtomSize = parent.readInt();
            int childAtomType = parent.readInt();
            if (childAtomType == Atom.TYPE_proj) {
                return Arrays.copyOfRange(parent.data, childPosition, childPosition + childAtomSize);
            }
            childPosition += childAtomSize;
        }
        return null;
    }

    private static int parseExpandableClassSize(ParsableByteArray data) {
        int currentByte = data.readUnsignedByte();
        int size = currentByte & 127;
        while ((currentByte & 128) == 128) {
            currentByte = data.readUnsignedByte();
            size = (size << 7) | (currentByte & 127);
        }
        return size;
    }

    private static boolean canApplyEditWithGaplessInfo(long[] timestamps, long duration, long editStartTime, long editEndTime) {
        int lastIndex = timestamps.length - 1;
        int latestDelayIndex = Util.constrainValue(3, 0, lastIndex);
        int earliestPaddingIndex = Util.constrainValue(timestamps.length - 3, 0, lastIndex);
        return timestamps[0] <= editStartTime && editStartTime < timestamps[latestDelayIndex] && timestamps[earliestPaddingIndex] < editEndTime && editEndTime <= duration;
    }

    private AtomParsers() {
    }

    private static final class ChunkIterator {
        private final ParsableByteArray chunkOffsets;
        private final boolean chunkOffsetsAreLongs;
        public int index;
        public final int length;
        private int nextSamplesPerChunkChangeIndex;
        public int numSamples;
        public long offset;
        private int remainingSamplesPerChunkChanges;
        private final ParsableByteArray stsc;

        public ChunkIterator(ParsableByteArray stsc, ParsableByteArray chunkOffsets, boolean chunkOffsetsAreLongs) {
            this.stsc = stsc;
            this.chunkOffsets = chunkOffsets;
            this.chunkOffsetsAreLongs = chunkOffsetsAreLongs;
            chunkOffsets.setPosition(12);
            this.length = chunkOffsets.readUnsignedIntToInt();
            stsc.setPosition(12);
            this.remainingSamplesPerChunkChanges = stsc.readUnsignedIntToInt();
            Assertions.checkState(stsc.readInt() == 1, "first_chunk must be 1");
            this.index = -1;
        }

        public boolean moveNext() {
            int i = this.index + 1;
            this.index = i;
            if (i == this.length) {
                return false;
            }
            this.offset = this.chunkOffsetsAreLongs ? this.chunkOffsets.readUnsignedLongToLong() : this.chunkOffsets.readUnsignedInt();
            if (this.index == this.nextSamplesPerChunkChangeIndex) {
                this.numSamples = this.stsc.readUnsignedIntToInt();
                this.stsc.skipBytes(4);
                int i2 = this.remainingSamplesPerChunkChanges - 1;
                this.remainingSamplesPerChunkChanges = i2;
                this.nextSamplesPerChunkChangeIndex = i2 > 0 ? this.stsc.readUnsignedIntToInt() - 1 : -1;
            }
            return true;
        }
    }

    private static final class TkhdData {
        private final long duration;
        private final int id;
        private final int rotationDegrees;

        public TkhdData(int id, long duration, int rotationDegrees) {
            this.id = id;
            this.duration = duration;
            this.rotationDegrees = rotationDegrees;
        }
    }

    private static final class StsdData {
        public static final int STSD_HEADER_SIZE = 8;
        public Format format;
        public int nalUnitLengthFieldLength;
        public int requiredSampleTransformation = 0;
        public final TrackEncryptionBox[] trackEncryptionBoxes;

        public StsdData(int numberOfEntries) {
            this.trackEncryptionBoxes = new TrackEncryptionBox[numberOfEntries];
        }
    }

    static final class StszSampleSizeBox implements SampleSizeBox {
        private final ParsableByteArray data;
        private final int fixedSampleSize;
        private final int sampleCount;

        public StszSampleSizeBox(Atom.LeafAtom stszAtom) {
            ParsableByteArray parsableByteArray = stszAtom.data;
            this.data = parsableByteArray;
            parsableByteArray.setPosition(12);
            this.fixedSampleSize = this.data.readUnsignedIntToInt();
            this.sampleCount = this.data.readUnsignedIntToInt();
        }

        @Override // com.google.android.exoplayer2.extractor.mp4.AtomParsers.SampleSizeBox
        public int getSampleCount() {
            return this.sampleCount;
        }

        @Override // com.google.android.exoplayer2.extractor.mp4.AtomParsers.SampleSizeBox
        public int readNextSampleSize() {
            int i = this.fixedSampleSize;
            return i == 0 ? this.data.readUnsignedIntToInt() : i;
        }

        @Override // com.google.android.exoplayer2.extractor.mp4.AtomParsers.SampleSizeBox
        public boolean isFixedSampleSize() {
            return this.fixedSampleSize != 0;
        }
    }

    static final class Stz2SampleSizeBox implements SampleSizeBox {
        private int currentByte;
        private final ParsableByteArray data;
        private final int fieldSize;
        private final int sampleCount;
        private int sampleIndex;

        public Stz2SampleSizeBox(Atom.LeafAtom stz2Atom) {
            ParsableByteArray parsableByteArray = stz2Atom.data;
            this.data = parsableByteArray;
            parsableByteArray.setPosition(12);
            this.fieldSize = this.data.readUnsignedIntToInt() & 255;
            this.sampleCount = this.data.readUnsignedIntToInt();
        }

        @Override // com.google.android.exoplayer2.extractor.mp4.AtomParsers.SampleSizeBox
        public int getSampleCount() {
            return this.sampleCount;
        }

        @Override // com.google.android.exoplayer2.extractor.mp4.AtomParsers.SampleSizeBox
        public int readNextSampleSize() {
            int i = this.fieldSize;
            if (i == 8) {
                return this.data.readUnsignedByte();
            }
            if (i == 16) {
                return this.data.readUnsignedShort();
            }
            int i2 = this.sampleIndex;
            this.sampleIndex = i2 + 1;
            if (i2 % 2 == 0) {
                int unsignedByte = this.data.readUnsignedByte();
                this.currentByte = unsignedByte;
                return (unsignedByte & PsExtractor.VIDEO_STREAM_MASK) >> 4;
            }
            return this.currentByte & 15;
        }

        @Override // com.google.android.exoplayer2.extractor.mp4.AtomParsers.SampleSizeBox
        public boolean isFixedSampleSize() {
            return false;
        }
    }
}
