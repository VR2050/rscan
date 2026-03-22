package p005b.p199l.p200a.p201a.p248o1;

import android.net.Uri;
import androidx.annotation.Nullable;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.MulticastSocket;
import java.net.SocketException;

/* renamed from: b.l.a.a.o1.g0 */
/* loaded from: classes.dex */
public final class C2293g0 extends AbstractC2294h {

    /* renamed from: a */
    public final int f5809a;

    /* renamed from: b */
    public final byte[] f5810b;

    /* renamed from: c */
    public final DatagramPacket f5811c;

    /* renamed from: d */
    @Nullable
    public Uri f5812d;

    /* renamed from: e */
    @Nullable
    public DatagramSocket f5813e;

    /* renamed from: f */
    @Nullable
    public MulticastSocket f5814f;

    /* renamed from: g */
    @Nullable
    public InetAddress f5815g;

    /* renamed from: h */
    @Nullable
    public InetSocketAddress f5816h;

    /* renamed from: i */
    public boolean f5817i;

    /* renamed from: j */
    public int f5818j;

    /* renamed from: b.l.a.a.o1.g0$a */
    public static final class a extends IOException {
        public a(IOException iOException) {
            super(iOException);
        }
    }

    public C2293g0() {
        super(true);
        this.f5809a = 8000;
        byte[] bArr = new byte[2000];
        this.f5810b = bArr;
        this.f5811c = new DatagramPacket(bArr, 0, 2000);
    }

    @Override // p005b.p199l.p200a.p201a.p248o1.InterfaceC2321m
    public void close() {
        this.f5812d = null;
        MulticastSocket multicastSocket = this.f5814f;
        if (multicastSocket != null) {
            try {
                multicastSocket.leaveGroup(this.f5815g);
            } catch (IOException unused) {
            }
            this.f5814f = null;
        }
        DatagramSocket datagramSocket = this.f5813e;
        if (datagramSocket != null) {
            datagramSocket.close();
            this.f5813e = null;
        }
        this.f5815g = null;
        this.f5816h = null;
        this.f5818j = 0;
        if (this.f5817i) {
            this.f5817i = false;
            transferEnded();
        }
    }

    @Override // p005b.p199l.p200a.p201a.p248o1.InterfaceC2321m
    @Nullable
    public Uri getUri() {
        return this.f5812d;
    }

    @Override // p005b.p199l.p200a.p201a.p248o1.InterfaceC2321m
    public long open(C2324p c2324p) {
        Uri uri = c2324p.f5933a;
        this.f5812d = uri;
        String host = uri.getHost();
        int port = this.f5812d.getPort();
        transferInitializing(c2324p);
        try {
            this.f5815g = InetAddress.getByName(host);
            this.f5816h = new InetSocketAddress(this.f5815g, port);
            if (this.f5815g.isMulticastAddress()) {
                MulticastSocket multicastSocket = new MulticastSocket(this.f5816h);
                this.f5814f = multicastSocket;
                multicastSocket.joinGroup(this.f5815g);
                this.f5813e = this.f5814f;
            } else {
                this.f5813e = new DatagramSocket(this.f5816h);
            }
            try {
                this.f5813e.setSoTimeout(this.f5809a);
                this.f5817i = true;
                transferStarted(c2324p);
                return -1L;
            } catch (SocketException e2) {
                throw new a(e2);
            }
        } catch (IOException e3) {
            throw new a(e3);
        }
    }

    @Override // p005b.p199l.p200a.p201a.p248o1.InterfaceC2321m
    public int read(byte[] bArr, int i2, int i3) {
        if (i3 == 0) {
            return 0;
        }
        if (this.f5818j == 0) {
            try {
                this.f5813e.receive(this.f5811c);
                int length = this.f5811c.getLength();
                this.f5818j = length;
                bytesTransferred(length);
            } catch (IOException e2) {
                throw new a(e2);
            }
        }
        int length2 = this.f5811c.getLength();
        int i4 = this.f5818j;
        int min = Math.min(i4, i3);
        System.arraycopy(this.f5810b, length2 - i4, bArr, i2, min);
        this.f5818j -= min;
        return min;
    }
}
