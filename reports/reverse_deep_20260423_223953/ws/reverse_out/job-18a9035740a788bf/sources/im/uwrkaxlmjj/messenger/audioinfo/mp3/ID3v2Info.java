package im.uwrkaxlmjj.messenger.audioinfo.mp3;

import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import androidx.recyclerview.widget.ItemTouchHelper;
import com.alibaba.fastjson.parser.JSONLexer;
import com.google.android.exoplayer2.metadata.id3.ApicFrame;
import com.google.android.exoplayer2.metadata.id3.CommentFrame;
import im.uwrkaxlmjj.messenger.audioinfo.AudioInfo;
import java.io.IOException;
import java.io.InputStream;
import java.util.logging.Level;
import java.util.logging.Logger;

/* JADX INFO: loaded from: classes2.dex */
public class ID3v2Info extends AudioInfo {
    static final Logger LOGGER = Logger.getLogger(ID3v2Info.class.getName());
    private byte coverPictureType;
    private final Level debugLevel;

    static class AttachedPicture {
        static final byte TYPE_COVER_FRONT = 3;
        static final byte TYPE_OTHER = 0;
        final String description;
        final byte[] imageData;
        final String imageType;
        final byte type;

        public AttachedPicture(byte type, String description, String imageType, byte[] imageData) {
            this.type = type;
            this.description = description;
            this.imageType = imageType;
            this.imageData = imageData;
        }
    }

    static class CommentOrUnsynchronizedLyrics {
        final String description;
        final String language;
        final String text;

        public CommentOrUnsynchronizedLyrics(String language, String description, String text) {
            this.language = language;
            this.description = description;
            this.text = text;
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:11:0x001e  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static boolean isID3v2StartPosition(java.io.InputStream r2) throws java.io.IOException {
        /*
            r0 = 3
            r2.mark(r0)
            int r0 = r2.read()     // Catch: java.lang.Throwable -> L23
            r1 = 73
            if (r0 != r1) goto L1e
            int r0 = r2.read()     // Catch: java.lang.Throwable -> L23
            r1 = 68
            if (r0 != r1) goto L1e
            int r0 = r2.read()     // Catch: java.lang.Throwable -> L23
            r1 = 51
            if (r0 != r1) goto L1e
            r0 = 1
            goto L1f
        L1e:
            r0 = 0
        L1f:
            r2.reset()
            return r0
        L23:
            r0 = move-exception
            r2.reset()
            throw r0
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.messenger.audioinfo.mp3.ID3v2Info.isID3v2StartPosition(java.io.InputStream):boolean");
    }

    public ID3v2Info(InputStream input) throws ID3v2Exception, IOException {
        this(input, Level.FINEST);
    }

    public ID3v2Info(InputStream input, Level debugLevel) throws ID3v2Exception, IOException {
        ID3v2DataInput data;
        long remainingLength;
        this.debugLevel = debugLevel;
        if (isID3v2StartPosition(input)) {
            ID3v2TagHeader tagHeader = new ID3v2TagHeader(input);
            this.brand = "ID3";
            this.version = String.format("2.%d.%d", Integer.valueOf(tagHeader.getVersion()), Integer.valueOf(tagHeader.getRevision()));
            ID3v2TagBody tagBody = tagHeader.tagBody(input);
            while (true) {
                try {
                    if (tagBody.getRemainingLength() <= 10) {
                        break;
                    }
                    ID3v2FrameHeader frameHeader = new ID3v2FrameHeader(tagBody);
                    if (frameHeader.isPadding()) {
                        break;
                    }
                    if (frameHeader.getBodySize() > tagBody.getRemainingLength()) {
                        if (LOGGER.isLoggable(debugLevel)) {
                            LOGGER.log(debugLevel, "ID3 frame claims to extend frames area");
                        }
                    } else if (!frameHeader.isValid() || frameHeader.isEncryption()) {
                        tagBody.getData().skipFully(frameHeader.getBodySize());
                    } else {
                        ID3v2FrameBody frameBody = tagBody.frameBody(frameHeader);
                        try {
                            try {
                                parseFrame(frameBody);
                                data = frameBody.getData();
                                remainingLength = frameBody.getRemainingLength();
                            } catch (ID3v2Exception e) {
                                if (LOGGER.isLoggable(debugLevel)) {
                                    LOGGER.log(debugLevel, String.format("ID3 exception occured in frame %s: %s", frameHeader.getFrameId(), e.getMessage()));
                                }
                                data = frameBody.getData();
                                remainingLength = frameBody.getRemainingLength();
                            }
                            data.skipFully(remainingLength);
                        } catch (Throwable th) {
                            frameBody.getData().skipFully(frameBody.getRemainingLength());
                            throw th;
                        }
                    }
                } catch (ID3v2Exception e2) {
                    if (LOGGER.isLoggable(debugLevel)) {
                        LOGGER.log(debugLevel, "ID3 exception occured: " + e2.getMessage());
                    }
                }
            }
            tagBody.getData().skipFully(tagBody.getRemainingLength());
            if (tagHeader.getFooterSize() > 0) {
                input.skip(tagHeader.getFooterSize());
            }
        }
    }

    /* JADX WARN: Failed to restore switch over string. Please report as a decompilation issue */
    void parseFrame(ID3v2FrameBody frame) throws ID3v2Exception, IOException {
        if (LOGGER.isLoggable(this.debugLevel)) {
            LOGGER.log(this.debugLevel, "Parsing frame: " + frame.getFrameHeader().getFrameId());
        }
        String frameId = frame.getFrameHeader().getFrameId();
        byte b = -1;
        switch (frameId.hashCode()) {
            case 66913:
                if (frameId.equals("COM")) {
                    b = 2;
                }
                break;
            case 79210:
                if (frameId.equals("PIC")) {
                    b = 0;
                }
                break;
            case 82815:
                if (frameId.equals("TAL")) {
                    b = 4;
                }
                break;
            case 82878:
                if (frameId.equals("TCM")) {
                    b = 8;
                }
                break;
            case 82880:
                if (frameId.equals("TCO")) {
                    b = 10;
                }
                break;
            case 82881:
                if (frameId.equals("TCP")) {
                    b = 6;
                }
                break;
            case 82883:
                if (frameId.equals("TCR")) {
                    b = 12;
                }
                break;
            case 83149:
                if (frameId.equals("TLE")) {
                    b = 15;
                }
                break;
            case 83253:
                if (frameId.equals("TP1")) {
                    b = 17;
                }
                break;
            case 83254:
                if (frameId.equals("TP2")) {
                    b = 19;
                }
                break;
            case 83269:
                if (frameId.equals("TPA")) {
                    b = 21;
                }
                break;
            case 83341:
                if (frameId.equals("TRK")) {
                    b = 23;
                }
                break;
            case 83377:
                if (frameId.equals("TT1")) {
                    b = 25;
                }
                break;
            case 83378:
                if (frameId.equals("TT2")) {
                    b = 27;
                }
                break;
            case 83552:
                if (frameId.equals("TYE")) {
                    b = 29;
                }
                break;
            case 84125:
                if (frameId.equals("ULT")) {
                    b = 31;
                }
                break;
            case 2015625:
                if (frameId.equals(ApicFrame.ID)) {
                    b = 1;
                }
                break;
            case 2074380:
                if (frameId.equals(CommentFrame.ID)) {
                    b = 3;
                }
                break;
            case 2567331:
                if (frameId.equals("TALB")) {
                    b = 5;
                }
                break;
            case 2569298:
                if (frameId.equals("TCMP")) {
                    b = 7;
                }
                break;
            case 2569357:
                if (frameId.equals("TCOM")) {
                    b = 9;
                }
                break;
            case 2569358:
                if (frameId.equals("TCON")) {
                    b = 11;
                }
                break;
            case 2569360:
                if (frameId.equals("TCOP")) {
                    b = 13;
                }
                break;
            case 2570401:
                if (frameId.equals("TDRC")) {
                    b = 14;
                }
                break;
            case 2575250:
                if (frameId.equals("TIT1")) {
                    b = JSONLexer.EOI;
                }
                break;
            case 2575251:
                if (frameId.equals("TIT2")) {
                    b = 28;
                }
                break;
            case 2577697:
                if (frameId.equals("TLEN")) {
                    b = 16;
                }
                break;
            case 2581512:
                if (frameId.equals("TPE1")) {
                    b = 18;
                }
                break;
            case 2581513:
                if (frameId.equals("TPE2")) {
                    b = 20;
                }
                break;
            case 2581856:
                if (frameId.equals("TPOS")) {
                    b = 22;
                }
                break;
            case 2583398:
                if (frameId.equals("TRCK")) {
                    b = 24;
                }
                break;
            case 2590194:
                if (frameId.equals("TYER")) {
                    b = 30;
                }
                break;
            case 2614438:
                if (frameId.equals("USLT")) {
                    b = 32;
                }
                break;
        }
        switch (b) {
            case 0:
            case 1:
                if (this.cover == null || this.coverPictureType != 3) {
                    AttachedPicture picture = parseAttachedPictureFrame(frame);
                    if (this.cover == null || picture.type == 3 || picture.type == 0) {
                        try {
                            byte[] bytes = picture.imageData;
                            BitmapFactory.Options opts = new BitmapFactory.Options();
                            opts.inJustDecodeBounds = true;
                            opts.inSampleSize = 1;
                            BitmapFactory.decodeByteArray(bytes, 0, bytes.length, opts);
                            if (opts.outWidth > 800 || opts.outHeight > 800) {
                                for (int size = Math.max(opts.outWidth, opts.outHeight); size > 800; size /= 2) {
                                    opts.inSampleSize *= 2;
                                }
                            }
                            opts.inJustDecodeBounds = false;
                            this.cover = BitmapFactory.decodeByteArray(bytes, 0, bytes.length, opts);
                            if (this.cover != null) {
                                float scale = Math.max(this.cover.getWidth(), this.cover.getHeight()) / 120.0f;
                                if (scale > 0.0f) {
                                    this.smallCover = Bitmap.createScaledBitmap(this.cover, (int) (this.cover.getWidth() / scale), (int) (this.cover.getHeight() / scale), true);
                                } else {
                                    this.smallCover = this.cover;
                                }
                                if (this.smallCover == null) {
                                    this.smallCover = this.cover;
                                }
                            }
                        } catch (Throwable e) {
                            e.printStackTrace();
                        }
                        this.coverPictureType = picture.type;
                    }
                }
                break;
            case 2:
            case 3:
                CommentOrUnsynchronizedLyrics comm = parseCommentOrUnsynchronizedLyricsFrame(frame);
                if (this.comment == null || comm.description == null || "".equals(comm.description)) {
                    this.comment = comm.text;
                }
                break;
            case 4:
            case 5:
                this.album = parseTextFrame(frame);
                break;
            case 6:
            case 7:
                this.compilation = "1".equals(parseTextFrame(frame));
                break;
            case 8:
            case 9:
                this.composer = parseTextFrame(frame);
                break;
            case 10:
            case 11:
                String tcon = parseTextFrame(frame);
                if (tcon.length() > 0) {
                    this.genre = tcon;
                    ID3v1Genre id3v1Genre = null;
                    try {
                        if (tcon.charAt(0) == '(') {
                            int pos = tcon.indexOf(41);
                            if (pos > 1 && (id3v1Genre = ID3v1Genre.getGenre(Integer.parseInt(tcon.substring(1, pos)))) == null && tcon.length() > pos + 1) {
                                this.genre = tcon.substring(pos + 1);
                            }
                        } else {
                            id3v1Genre = ID3v1Genre.getGenre(Integer.parseInt(tcon));
                        }
                        if (id3v1Genre != null) {
                            this.genre = id3v1Genre.getDescription();
                        }
                    } catch (NumberFormatException e2) {
                        return;
                    }
                }
                break;
            case 12:
            case 13:
                this.copyright = parseTextFrame(frame);
                break;
            case 14:
                String tdrc = parseTextFrame(frame);
                if (tdrc.length() >= 4) {
                    try {
                        this.year = Short.valueOf(tdrc.substring(0, 4)).shortValue();
                    } catch (NumberFormatException e3) {
                        if (LOGGER.isLoggable(this.debugLevel)) {
                            LOGGER.log(this.debugLevel, "Could not parse year from: " + tdrc);
                            return;
                        }
                        return;
                    }
                }
                break;
            case 15:
            case 16:
                String tlen = parseTextFrame(frame);
                try {
                    this.duration = Long.valueOf(tlen).longValue();
                } catch (NumberFormatException e4) {
                    if (LOGGER.isLoggable(this.debugLevel)) {
                        LOGGER.log(this.debugLevel, "Could not parse track duration: " + tlen);
                        return;
                    }
                    return;
                }
                break;
            case 17:
            case 18:
                this.artist = parseTextFrame(frame);
                break;
            case 19:
            case 20:
                this.albumArtist = parseTextFrame(frame);
                break;
            case 21:
            case 22:
                String tpos = parseTextFrame(frame);
                if (tpos.length() > 0) {
                    int index = tpos.indexOf(47);
                    if (index < 0) {
                        try {
                            this.disc = Short.valueOf(tpos).shortValue();
                        } catch (NumberFormatException e5) {
                            if (LOGGER.isLoggable(this.debugLevel)) {
                                LOGGER.log(this.debugLevel, "Could not parse disc number: " + tpos);
                                return;
                            }
                            return;
                        }
                    } else {
                        try {
                            this.disc = Short.valueOf(tpos.substring(0, index)).shortValue();
                        } catch (NumberFormatException e6) {
                            if (LOGGER.isLoggable(this.debugLevel)) {
                                LOGGER.log(this.debugLevel, "Could not parse disc number: " + tpos);
                            }
                        }
                        try {
                            this.discs = Short.valueOf(tpos.substring(index + 1)).shortValue();
                        } catch (NumberFormatException e7) {
                            if (LOGGER.isLoggable(this.debugLevel)) {
                                LOGGER.log(this.debugLevel, "Could not parse number of discs: " + tpos);
                                return;
                            }
                            return;
                        }
                    }
                }
                break;
            case 23:
            case 24:
                String trck = parseTextFrame(frame);
                if (trck.length() > 0) {
                    int index2 = trck.indexOf(47);
                    if (index2 < 0) {
                        try {
                            this.track = Short.valueOf(trck).shortValue();
                        } catch (NumberFormatException e8) {
                            if (LOGGER.isLoggable(this.debugLevel)) {
                                LOGGER.log(this.debugLevel, "Could not parse track number: " + trck);
                                return;
                            }
                            return;
                        }
                    } else {
                        try {
                            this.track = Short.valueOf(trck.substring(0, index2)).shortValue();
                        } catch (NumberFormatException e9) {
                            if (LOGGER.isLoggable(this.debugLevel)) {
                                LOGGER.log(this.debugLevel, "Could not parse track number: " + trck);
                            }
                        }
                        try {
                            this.tracks = Short.valueOf(trck.substring(index2 + 1)).shortValue();
                        } catch (NumberFormatException e10) {
                            if (LOGGER.isLoggable(this.debugLevel)) {
                                LOGGER.log(this.debugLevel, "Could not parse number of tracks: " + trck);
                                return;
                            }
                            return;
                        }
                    }
                }
                break;
            case 25:
            case 26:
                this.grouping = parseTextFrame(frame);
                break;
            case 27:
            case 28:
                this.title = parseTextFrame(frame);
                break;
            case 29:
            case 30:
                String tyer = parseTextFrame(frame);
                if (tyer.length() > 0) {
                    try {
                        this.year = Short.valueOf(tyer).shortValue();
                    } catch (NumberFormatException e11) {
                        if (LOGGER.isLoggable(this.debugLevel)) {
                            LOGGER.log(this.debugLevel, "Could not parse year: " + tyer);
                            return;
                        }
                        return;
                    }
                }
                break;
            case 31:
            case 32:
                if (this.lyrics == null) {
                    this.lyrics = parseCommentOrUnsynchronizedLyricsFrame(frame).text;
                }
                break;
        }
    }

    String parseTextFrame(ID3v2FrameBody frame) throws ID3v2Exception, IOException {
        ID3v2Encoding encoding = frame.readEncoding();
        return frame.readFixedLengthString((int) frame.getRemainingLength(), encoding);
    }

    CommentOrUnsynchronizedLyrics parseCommentOrUnsynchronizedLyricsFrame(ID3v2FrameBody data) throws ID3v2Exception, IOException {
        ID3v2Encoding encoding = data.readEncoding();
        String language = data.readFixedLengthString(3, ID3v2Encoding.ISO_8859_1);
        String description = data.readZeroTerminatedString(ItemTouchHelper.Callback.DEFAULT_DRAG_ANIMATION_DURATION, encoding);
        String text = data.readFixedLengthString((int) data.getRemainingLength(), encoding);
        return new CommentOrUnsynchronizedLyrics(language, description, text);
    }

    AttachedPicture parseAttachedPictureFrame(ID3v2FrameBody data) throws ID3v2Exception, IOException {
        String imageType;
        ID3v2Encoding encoding = data.readEncoding();
        if (data.getTagHeader().getVersion() == 2) {
            String fileType = data.readFixedLengthString(3, ID3v2Encoding.ISO_8859_1);
            String upperCase = fileType.toUpperCase();
            byte b = -1;
            int iHashCode = upperCase.hashCode();
            if (iHashCode != 73665) {
                if (iHashCode == 79369 && upperCase.equals("PNG")) {
                    b = 0;
                }
            } else if (upperCase.equals("JPG")) {
                b = 1;
            }
            if (b == 0) {
                imageType = "image/png";
            } else if (b == 1) {
                imageType = "image/jpeg";
            } else {
                imageType = "image/unknown";
            }
        } else {
            imageType = data.readZeroTerminatedString(20, ID3v2Encoding.ISO_8859_1);
        }
        byte pictureType = data.getData().readByte();
        String description = data.readZeroTerminatedString(ItemTouchHelper.Callback.DEFAULT_DRAG_ANIMATION_DURATION, encoding);
        byte[] imageData = data.getData().readFully((int) data.getRemainingLength());
        return new AttachedPicture(pictureType, description, imageType, imageData);
    }
}
