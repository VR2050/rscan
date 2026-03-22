package tv.danmaku.ijk.media.exo2.source;

import androidx.annotation.Nullable;
import p005b.p199l.p200a.p201a.p248o1.InterfaceC2291f0;
import p005b.p199l.p200a.p201a.p248o1.InterfaceC2333y;

/* loaded from: classes3.dex */
public final class GSYExoHttpDataSourceFactory extends InterfaceC2333y.a {
    private final boolean allowCrossProtocolRedirects;
    private final int connectTimeoutMillis;

    @Nullable
    private final InterfaceC2291f0 listener;
    private final int readTimeoutMillis;
    private final String userAgent;

    public GSYExoHttpDataSourceFactory(String str) {
        this(str, null);
    }

    public GSYExoHttpDataSourceFactory(String str, @Nullable InterfaceC2291f0 interfaceC2291f0) {
        this(str, interfaceC2291f0, 8000, 8000, false);
    }

    @Override // p005b.p199l.p200a.p201a.p248o1.InterfaceC2333y.a
    public GSYDefaultHttpDataSource createDataSourceInternal(InterfaceC2333y.e eVar) {
        GSYDefaultHttpDataSource gSYDefaultHttpDataSource = new GSYDefaultHttpDataSource(this.userAgent, this.connectTimeoutMillis, this.readTimeoutMillis, this.allowCrossProtocolRedirects, eVar);
        InterfaceC2291f0 interfaceC2291f0 = this.listener;
        if (interfaceC2291f0 != null) {
            gSYDefaultHttpDataSource.addTransferListener(interfaceC2291f0);
        }
        return gSYDefaultHttpDataSource;
    }

    public GSYExoHttpDataSourceFactory(String str, int i2, int i3, boolean z) {
        this(str, null, i2, i3, z);
    }

    public GSYExoHttpDataSourceFactory(String str, @Nullable InterfaceC2291f0 interfaceC2291f0, int i2, int i3, boolean z) {
        this.userAgent = str;
        this.listener = interfaceC2291f0;
        this.connectTimeoutMillis = i2;
        this.readTimeoutMillis = i3;
        this.allowCrossProtocolRedirects = z;
    }
}
