package p005b.p199l.p200a.p201a.p220h1.p222h;

import com.google.android.exoplayer2.metadata.Metadata;
import com.google.android.exoplayer2.metadata.icy.IcyInfo;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.Charset;
import java.nio.charset.CharsetDecoder;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import p005b.p199l.p200a.p201a.p220h1.C2081d;
import p005b.p199l.p200a.p201a.p220h1.InterfaceC2079b;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;

/* renamed from: b.l.a.a.h1.h.a */
/* loaded from: classes.dex */
public final class C2086a implements InterfaceC2079b {

    /* renamed from: a */
    public static final Pattern f4385a = Pattern.compile("(.+?)='(.*?)';", 32);

    /* renamed from: b */
    public final CharsetDecoder f4386b = Charset.forName("UTF-8").newDecoder();

    /* renamed from: c */
    public final CharsetDecoder f4387c = Charset.forName("ISO-8859-1").newDecoder();

    @Override // p005b.p199l.p200a.p201a.p220h1.InterfaceC2079b
    /* renamed from: a */
    public Metadata mo1705a(C2081d c2081d) {
        String str;
        ByteBuffer byteBuffer = c2081d.f3306e;
        Objects.requireNonNull(byteBuffer);
        String str2 = null;
        try {
            str = this.f4386b.decode(byteBuffer).toString();
        } catch (CharacterCodingException unused) {
            try {
                str = this.f4387c.decode(byteBuffer).toString();
                this.f4387c.reset();
                byteBuffer.rewind();
            } catch (CharacterCodingException unused2) {
                this.f4387c.reset();
                byteBuffer.rewind();
                str = null;
            } catch (Throwable th) {
                this.f4387c.reset();
                byteBuffer.rewind();
                throw th;
            }
        } finally {
            this.f4386b.reset();
            byteBuffer.rewind();
        }
        byte[] bArr = new byte[byteBuffer.limit()];
        byteBuffer.get(bArr);
        if (str == null) {
            return new Metadata(new IcyInfo(bArr, null, null));
        }
        Matcher matcher = f4385a.matcher(str);
        String str3 = null;
        for (int i2 = 0; matcher.find(i2); i2 = matcher.end()) {
            String m2320L = C2344d0.m2320L(matcher.group(1));
            String group = matcher.group(2);
            m2320L.hashCode();
            if (m2320L.equals("streamurl")) {
                str3 = group;
            } else if (m2320L.equals("streamtitle")) {
                str2 = group;
            }
        }
        return new Metadata(new IcyInfo(bArr, str2, str3));
    }
}
