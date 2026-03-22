package p005b.p199l.p200a.p201a.p220h1.p221g;

import com.google.android.exoplayer2.metadata.emsg.EventMessage;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;

/* renamed from: b.l.a.a.h1.g.b */
/* loaded from: classes.dex */
public final class C2085b {

    /* renamed from: a */
    public final ByteArrayOutputStream f4383a;

    /* renamed from: b */
    public final DataOutputStream f4384b;

    public C2085b() {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream(512);
        this.f4383a = byteArrayOutputStream;
        this.f4384b = new DataOutputStream(byteArrayOutputStream);
    }

    /* renamed from: b */
    public static void m1710b(DataOutputStream dataOutputStream, long j2) {
        dataOutputStream.writeByte(((int) (j2 >>> 24)) & 255);
        dataOutputStream.writeByte(((int) (j2 >>> 16)) & 255);
        dataOutputStream.writeByte(((int) (j2 >>> 8)) & 255);
        dataOutputStream.writeByte(((int) j2) & 255);
    }

    /* renamed from: a */
    public byte[] m1711a(EventMessage eventMessage) {
        this.f4383a.reset();
        try {
            DataOutputStream dataOutputStream = this.f4384b;
            dataOutputStream.writeBytes(eventMessage.f9276f);
            dataOutputStream.writeByte(0);
            String str = eventMessage.f9277g;
            if (str == null) {
                str = "";
            }
            DataOutputStream dataOutputStream2 = this.f4384b;
            dataOutputStream2.writeBytes(str);
            dataOutputStream2.writeByte(0);
            m1710b(this.f4384b, eventMessage.f9278h);
            m1710b(this.f4384b, eventMessage.f9279i);
            this.f4384b.write(eventMessage.f9280j);
            this.f4384b.flush();
            return this.f4383a.toByteArray();
        } catch (IOException e2) {
            throw new RuntimeException(e2);
        }
    }
}
