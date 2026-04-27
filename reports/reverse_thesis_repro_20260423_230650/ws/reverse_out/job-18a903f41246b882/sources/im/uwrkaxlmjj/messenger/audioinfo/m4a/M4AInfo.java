package im.uwrkaxlmjj.messenger.audioinfo.m4a;

import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import com.coremedia.iso.boxes.FileTypeBox;
import com.coremedia.iso.boxes.MediaBox;
import com.coremedia.iso.boxes.MediaHeaderBox;
import com.coremedia.iso.boxes.MetaBox;
import com.coremedia.iso.boxes.MovieBox;
import com.coremedia.iso.boxes.MovieHeaderBox;
import com.coremedia.iso.boxes.TrackBox;
import com.coremedia.iso.boxes.UserDataBox;
import com.coremedia.iso.boxes.apple.AppleItemListBox;
import im.uwrkaxlmjj.messenger.audioinfo.AudioInfo;
import im.uwrkaxlmjj.messenger.audioinfo.mp3.ID3v1Genre;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigDecimal;
import java.util.logging.Level;
import java.util.logging.Logger;

/* JADX INFO: loaded from: classes2.dex */
public class M4AInfo extends AudioInfo {
    private static final String ASCII = "ISO8859_1";
    static final Logger LOGGER = Logger.getLogger(M4AInfo.class.getName());
    private static final String UTF_8 = "UTF-8";
    private final Level debugLevel;
    private byte rating;
    private BigDecimal speed;
    private short tempo;
    private BigDecimal volume;

    public M4AInfo(InputStream input) throws IOException {
        this(input, Level.FINEST);
    }

    public M4AInfo(InputStream input, Level debugLevel) throws IOException {
        this.debugLevel = debugLevel;
        MP4Input mp4 = new MP4Input(input);
        if (LOGGER.isLoggable(debugLevel)) {
            LOGGER.log(debugLevel, mp4.toString());
        }
        ftyp(mp4.nextChild(FileTypeBox.TYPE));
        moov(mp4.nextChildUpTo(MovieBox.TYPE));
    }

    void ftyp(MP4Atom atom) throws IOException {
        if (LOGGER.isLoggable(this.debugLevel)) {
            LOGGER.log(this.debugLevel, atom.toString());
        }
        this.brand = atom.readString(4, ASCII).trim();
        if (this.brand.matches("M4V|MP4|mp42|isom")) {
            LOGGER.warning(atom.getPath() + ": brand=" + this.brand + " (experimental)");
        } else if (!this.brand.matches("M4A|M4P")) {
            LOGGER.warning(atom.getPath() + ": brand=" + this.brand + " (expected M4A or M4P)");
        }
        this.version = String.valueOf(atom.readInt());
    }

    void moov(MP4Atom atom) throws IOException {
        if (LOGGER.isLoggable(this.debugLevel)) {
            LOGGER.log(this.debugLevel, atom.toString());
        }
        while (atom.hasMoreChildren()) {
            MP4Atom child = atom.nextChild();
            String type = child.getType();
            byte b = -1;
            int iHashCode = type.hashCode();
            if (iHashCode != 3363941) {
                if (iHashCode != 3568424) {
                    if (iHashCode == 3585340 && type.equals(UserDataBox.TYPE)) {
                        b = 2;
                    }
                } else if (type.equals(TrackBox.TYPE)) {
                    b = 1;
                }
            } else if (type.equals(MovieHeaderBox.TYPE)) {
                b = 0;
            }
            if (b == 0) {
                mvhd(child);
            } else if (b == 1) {
                trak(child);
            } else if (b == 2) {
                udta(child);
            }
        }
    }

    void mvhd(MP4Atom atom) throws IOException {
        if (LOGGER.isLoggable(this.debugLevel)) {
            LOGGER.log(this.debugLevel, atom.toString());
        }
        byte version = atom.readByte();
        atom.skip(3);
        atom.skip(version == 1 ? 16 : 8);
        int scale = atom.readInt();
        long units = version == 1 ? atom.readLong() : atom.readInt();
        if (this.duration == 0) {
            this.duration = (1000 * units) / ((long) scale);
        } else if (LOGGER.isLoggable(this.debugLevel) && Math.abs(this.duration - ((units * 1000) / ((long) scale))) > 2) {
            LOGGER.log(this.debugLevel, "mvhd: duration " + this.duration + " -> " + ((1000 * units) / ((long) scale)));
        }
        this.speed = atom.readIntegerFixedPoint();
        this.volume = atom.readShortFixedPoint();
    }

    void trak(MP4Atom atom) throws IOException {
        if (LOGGER.isLoggable(this.debugLevel)) {
            LOGGER.log(this.debugLevel, atom.toString());
        }
        mdia(atom.nextChildUpTo(MediaBox.TYPE));
    }

    void mdia(MP4Atom atom) throws IOException {
        if (LOGGER.isLoggable(this.debugLevel)) {
            LOGGER.log(this.debugLevel, atom.toString());
        }
        mdhd(atom.nextChild(MediaHeaderBox.TYPE));
    }

    void mdhd(MP4Atom atom) throws IOException {
        if (LOGGER.isLoggable(this.debugLevel)) {
            LOGGER.log(this.debugLevel, atom.toString());
        }
        byte version = atom.readByte();
        atom.skip(3);
        atom.skip(version == 1 ? 16 : 8);
        int sampleRate = atom.readInt();
        long samples = version == 1 ? atom.readLong() : atom.readInt();
        if (this.duration == 0) {
            this.duration = (1000 * samples) / ((long) sampleRate);
            return;
        }
        if (LOGGER.isLoggable(this.debugLevel) && Math.abs(this.duration - ((samples * 1000) / ((long) sampleRate))) > 2) {
            LOGGER.log(this.debugLevel, "mdhd: duration " + this.duration + " -> " + ((1000 * samples) / ((long) sampleRate)));
        }
    }

    void udta(MP4Atom atom) throws IOException {
        if (LOGGER.isLoggable(this.debugLevel)) {
            LOGGER.log(this.debugLevel, atom.toString());
        }
        while (atom.hasMoreChildren()) {
            MP4Atom child = atom.nextChild();
            if (MetaBox.TYPE.equals(child.getType())) {
                meta(child);
                return;
            }
        }
    }

    void meta(MP4Atom atom) throws IOException {
        if (LOGGER.isLoggable(this.debugLevel)) {
            LOGGER.log(this.debugLevel, atom.toString());
        }
        atom.skip(4);
        while (atom.hasMoreChildren()) {
            MP4Atom child = atom.nextChild();
            if (AppleItemListBox.TYPE.equals(child.getType())) {
                ilst(child);
                return;
            }
        }
    }

    void ilst(MP4Atom atom) throws IOException {
        if (LOGGER.isLoggable(this.debugLevel)) {
            LOGGER.log(this.debugLevel, atom.toString());
        }
        while (atom.hasMoreChildren()) {
            MP4Atom child = atom.nextChild();
            if (LOGGER.isLoggable(this.debugLevel)) {
                LOGGER.log(this.debugLevel, child.toString());
            }
            if (child.getRemaining() == 0) {
                if (LOGGER.isLoggable(this.debugLevel)) {
                    LOGGER.log(this.debugLevel, child.getPath() + ": contains no value");
                }
            } else {
                data(child.nextChildUpTo("data"));
            }
        }
    }

    void data(MP4Atom atom) throws IOException {
        if (LOGGER.isLoggable(this.debugLevel)) {
            LOGGER.log(this.debugLevel, atom.toString());
        }
        atom.skip(4);
        atom.skip(4);
        switch (atom.getParent().getType()) {
            case "©alb":
                this.album = atom.readString("UTF-8");
                break;
            case "aART":
                this.albumArtist = atom.readString("UTF-8");
                break;
            case "©ART":
                this.artist = atom.readString("UTF-8");
                break;
            case "©cmt":
                this.comment = atom.readString("UTF-8");
                break;
            case "©com":
            case "©wrt":
                if (this.composer == null || this.composer.trim().length() == 0) {
                    this.composer = atom.readString("UTF-8");
                    break;
                }
                break;
            case "covr":
                try {
                    byte[] bytes = atom.readBytes();
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
                    break;
                } catch (Exception e) {
                    e.printStackTrace();
                    return;
                }
                break;
            case "cpil":
                this.compilation = atom.readBoolean();
                break;
            case "cprt":
            case "©cpy":
                if (this.copyright == null || this.copyright.trim().length() == 0) {
                    this.copyright = atom.readString("UTF-8");
                    break;
                }
                break;
            case "©day":
                String day = atom.readString("UTF-8").trim();
                if (day.length() >= 4) {
                    try {
                        this.year = Short.valueOf(day.substring(0, 4)).shortValue();
                    } catch (NumberFormatException e2) {
                        return;
                    }
                    break;
                }
                break;
            case "disk":
                atom.skip(2);
                this.disc = atom.readShort();
                this.discs = atom.readShort();
                break;
            case "gnre":
                if (this.genre == null || this.genre.trim().length() == 0) {
                    if (atom.getRemaining() == 2) {
                        int index = atom.readShort() - 1;
                        ID3v1Genre id3v1Genre = ID3v1Genre.getGenre(index);
                        if (id3v1Genre != null) {
                            this.genre = id3v1Genre.getDescription();
                        }
                    } else {
                        this.genre = atom.readString("UTF-8");
                    }
                    break;
                }
                break;
            case "©gen":
                if (this.genre == null || this.genre.trim().length() == 0) {
                    this.genre = atom.readString("UTF-8");
                    break;
                }
                break;
            case "©grp":
                this.grouping = atom.readString("UTF-8");
                break;
            case "©lyr":
                this.lyrics = atom.readString("UTF-8");
                break;
            case "©nam":
                this.title = atom.readString("UTF-8");
                break;
            case "rtng":
                this.rating = atom.readByte();
                break;
            case "tmpo":
                this.tempo = atom.readShort();
                break;
            case "trkn":
                atom.skip(2);
                this.track = atom.readShort();
                this.tracks = atom.readShort();
                break;
        }
    }

    public short getTempo() {
        return this.tempo;
    }

    public byte getRating() {
        return this.rating;
    }

    public BigDecimal getSpeed() {
        return this.speed;
    }

    public BigDecimal getVolume() {
        return this.volume;
    }
}
