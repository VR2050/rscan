package p005b.p143g.p144a.p147m.p148s;

import android.content.res.AssetManager;
import android.util.Log;
import androidx.annotation.NonNull;
import java.io.IOException;
import p005b.p143g.p144a.EnumC1556f;
import p005b.p143g.p144a.p147m.EnumC1569a;
import p005b.p143g.p144a.p147m.p148s.InterfaceC1590d;

/* renamed from: b.g.a.m.s.b */
/* loaded from: classes.dex */
public abstract class AbstractC1588b<T> implements InterfaceC1590d<T> {

    /* renamed from: c */
    public final String f1999c;

    /* renamed from: e */
    public final AssetManager f2000e;

    /* renamed from: f */
    public T f2001f;

    public AbstractC1588b(AssetManager assetManager, String str) {
        this.f2000e = assetManager;
        this.f1999c = str;
    }

    @Override // p005b.p143g.p144a.p147m.p148s.InterfaceC1590d
    /* renamed from: b */
    public void mo835b() {
        T t = this.f2001f;
        if (t == null) {
            return;
        }
        try {
            mo836c(t);
        } catch (IOException unused) {
        }
    }

    /* renamed from: c */
    public abstract void mo836c(T t);

    @Override // p005b.p143g.p144a.p147m.p148s.InterfaceC1590d
    public void cancel() {
    }

    @Override // p005b.p143g.p144a.p147m.p148s.InterfaceC1590d
    /* renamed from: d */
    public void mo837d(@NonNull EnumC1556f enumC1556f, @NonNull InterfaceC1590d.a<? super T> aVar) {
        try {
            T mo838e = mo838e(this.f2000e, this.f1999c);
            this.f2001f = mo838e;
            aVar.mo840e(mo838e);
        } catch (IOException e2) {
            Log.isLoggable("AssetPathFetcher", 3);
            aVar.mo839c(e2);
        }
    }

    /* renamed from: e */
    public abstract T mo838e(AssetManager assetManager, String str);

    @Override // p005b.p143g.p144a.p147m.p148s.InterfaceC1590d
    @NonNull
    public EnumC1569a getDataSource() {
        return EnumC1569a.LOCAL;
    }
}
