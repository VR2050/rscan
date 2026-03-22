package p005b.p199l.p200a.p201a.p208f1.p211c0;

import androidx.annotation.Nullable;
import androidx.annotation.VisibleForTesting;
import com.google.android.exoplayer2.Format;
import com.google.android.exoplayer2.extractor.mp4.MdtaMetadataEntry;
import com.google.android.exoplayer2.metadata.Metadata;
import com.google.android.exoplayer2.metadata.id3.CommentFrame;
import com.google.android.exoplayer2.metadata.id3.Id3Frame;
import com.google.android.exoplayer2.metadata.id3.TextInformationFrame;
import java.nio.ByteBuffer;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p208f1.C2046m;
import p005b.p199l.p200a.p201a.p250p1.C2360t;

/* renamed from: b.l.a.a.f1.c0.e */
/* loaded from: classes.dex */
public final class C1985e {

    /* renamed from: a */
    @VisibleForTesting
    public static final String[] f3651a = {"Blues", "Classic Rock", "Country", "Dance", "Disco", "Funk", "Grunge", "Hip-Hop", "Jazz", "Metal", "New Age", "Oldies", "Other", "Pop", "R&B", "Rap", "Reggae", "Rock", "Techno", "Industrial", "Alternative", "Ska", "Death Metal", "Pranks", "Soundtrack", "Euro-Techno", "Ambient", "Trip-Hop", "Vocal", "Jazz+Funk", "Fusion", "Trance", "Classical", "Instrumental", "Acid", "House", "Game", "Sound Clip", "Gospel", "Noise", "AlternRock", "Bass", "Soul", "Punk", "Space", "Meditative", "Instrumental Pop", "Instrumental Rock", "Ethnic", "Gothic", "Darkwave", "Techno-Industrial", "Electronic", "Pop-Folk", "Eurodance", "Dream", "Southern Rock", "Comedy", "Cult", "Gangsta", "Top 40", "Christian Rap", "Pop/Funk", "Jungle", "Native American", "Cabaret", "New Wave", "Psychadelic", "Rave", "Showtunes", "Trailer", "Lo-Fi", "Tribal", "Acid Punk", "Acid Jazz", "Polka", "Retro", "Musical", "Rock & Roll", "Hard Rock", "Folk", "Folk-Rock", "National Folk", "Swing", "Fast Fusion", "Bebob", "Latin", "Revival", "Celtic", "Bluegrass", "Avantgarde", "Gothic Rock", "Progressive Rock", "Psychedelic Rock", "Symphonic Rock", "Slow Rock", "Big Band", "Chorus", "Easy Listening", "Acoustic", "Humour", "Speech", "Chanson", "Opera", "Chamber Music", "Sonata", "Symphony", "Booty Bass", "Primus", "Porn Groove", "Satire", "Slow Jam", "Club", "Tango", "Samba", "Folklore", "Ballad", "Power Ballad", "Rhythmic Soul", "Freestyle", "Duet", "Punk Rock", "Drum Solo", "A capella", "Euro-House", "Dance Hall", "Goa", "Drum & Bass", "Club-House", "Hardcore", "Terror", "Indie", "BritPop", "Afro-Punk", "Polsk Punk", "Beat", "Christian Gangsta Rap", "Heavy Metal", "Black Metal", "Crossover", "Contemporary Christian", "Christian Rock", "Merengue", "Salsa", "Thrash Metal", "Anime", "Jpop", "Synthpop", "Abstract", "Art Rock", "Baroque", "Bhangra", "Big beat", "Breakbeat", "Chillout", "Downtempo", "Dub", "EBM", "Eclectic", "Electro", "Electroclash", "Emo", "Experimental", "Garage", "Global", "IDM", "Illbient", "Industro-Goth", "Jam Band", "Krautrock", "Leftfield", "Lounge", "Math Rock", "New Romantic", "Nu-Breakz", "Post-Punk", "Post-Rock", "Psytrance", "Shoegaze", "Space Rock", "Trop Rock", "World Music", "Neoclassical", "Audiobook", "Audio theatre", "Neue Deutsche Welle", "Podcast", "Indie-Rock", "G-Funk", "Dubstep", "Garage Rock", "Psybient"};

    /* renamed from: a */
    public static Format m1530a(int i2, Format format, @Nullable Metadata metadata, @Nullable Metadata metadata2, C2046m c2046m) {
        boolean z = false;
        if (i2 == 1) {
            int i3 = c2046m.f4170b;
            if (i3 != -1 && c2046m.f4171c != -1) {
                z = true;
            }
            if (z) {
                format = format.m4045o(i3, c2046m.f4171c);
            }
            return metadata != null ? format.m4042b(format.f9248o, metadata) : format;
        }
        if (i2 != 2 || metadata2 == null) {
            return format;
        }
        int i4 = 0;
        while (true) {
            Metadata.Entry[] entryArr = metadata2.f9273c;
            if (i4 >= entryArr.length) {
                return format;
            }
            Metadata.Entry entry = entryArr[i4];
            if (entry instanceof MdtaMetadataEntry) {
                MdtaMetadataEntry mdtaMetadataEntry = (MdtaMetadataEntry) entry;
                if ("com.android.capture.fps".equals(mdtaMetadataEntry.f9269c) && mdtaMetadataEntry.f9272g == 23) {
                    try {
                        Format m4044k = format.m4044k(ByteBuffer.wrap(mdtaMetadataEntry.f9270e).asFloatBuffer().get());
                        format = m4044k.m4042b(m4044k.f9248o, new Metadata(mdtaMetadataEntry));
                    } catch (NumberFormatException unused) {
                    }
                }
            }
            i4++;
        }
    }

    @Nullable
    /* renamed from: b */
    public static TextInformationFrame m1531b(int i2, String str, C2360t c2360t) {
        int m2573e = c2360t.m2573e();
        if (c2360t.m2573e() == 1684108385 && m2573e >= 22) {
            c2360t.m2568D(10);
            int m2590v = c2360t.m2590v();
            if (m2590v > 0) {
                String m626l = C1499a.m626l("", m2590v);
                int m2590v2 = c2360t.m2590v();
                if (m2590v2 > 0) {
                    m626l = m626l + "/" + m2590v2;
                }
                return new TextInformationFrame(str, null, m626l);
            }
        }
        AbstractC1981a.m1509a(i2);
        return null;
    }

    @Nullable
    /* renamed from: c */
    public static TextInformationFrame m1532c(int i2, String str, C2360t c2360t) {
        int m2573e = c2360t.m2573e();
        if (c2360t.m2573e() == 1684108385) {
            c2360t.m2568D(8);
            return new TextInformationFrame(str, null, c2360t.m2581m(m2573e - 16));
        }
        AbstractC1981a.m1509a(i2);
        return null;
    }

    @Nullable
    /* renamed from: d */
    public static Id3Frame m1533d(int i2, String str, C2360t c2360t, boolean z, boolean z2) {
        int m1534e = m1534e(c2360t);
        if (z2) {
            m1534e = Math.min(1, m1534e);
        }
        if (m1534e >= 0) {
            return z ? new TextInformationFrame(str, null, Integer.toString(m1534e)) : new CommentFrame("und", str, Integer.toString(m1534e));
        }
        AbstractC1981a.m1509a(i2);
        return null;
    }

    /* renamed from: e */
    public static int m1534e(C2360t c2360t) {
        c2360t.m2568D(4);
        if (c2360t.m2573e() != 1684108385) {
            return -1;
        }
        c2360t.m2568D(8);
        return c2360t.m2585q();
    }
}
