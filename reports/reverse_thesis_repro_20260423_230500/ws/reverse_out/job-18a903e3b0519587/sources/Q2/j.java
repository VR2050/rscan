package Q2;

import java.io.OutputStream;
import java.nio.channels.WritableByteChannel;

/* JADX INFO: loaded from: classes.dex */
public interface j extends D, WritableByteChannel {
    j E(int i3);

    j L(int i3);

    j Q(byte[] bArr);

    j S();

    i e();

    @Override // Q2.D, java.io.Flushable
    void flush();

    j j(byte[] bArr, int i3, int i4);

    j j0(String str);

    j k0(long j3);

    OutputStream l0();

    j n(long j3);

    long o(F f3);

    j u();

    j w(int i3);

    j z(l lVar);
}
