package p005b.p143g.p144a.p147m.p148s;

import android.content.ContentResolver;
import android.net.Uri;
import android.util.Log;
import androidx.annotation.NonNull;
import java.io.FileNotFoundException;
import java.io.IOException;
import p005b.p143g.p144a.EnumC1556f;
import p005b.p143g.p144a.p147m.EnumC1569a;
import p005b.p143g.p144a.p147m.p148s.InterfaceC1590d;

/* renamed from: b.g.a.m.s.l */
/* loaded from: classes.dex */
public abstract class AbstractC1598l<T> implements InterfaceC1590d<T> {

    /* renamed from: c */
    public final Uri f2022c;

    /* renamed from: e */
    public final ContentResolver f2023e;

    /* renamed from: f */
    public T f2024f;

    public AbstractC1598l(ContentResolver contentResolver, Uri uri) {
        this.f2023e = contentResolver;
        this.f2022c = uri;
    }

    @Override // p005b.p143g.p144a.p147m.p148s.InterfaceC1590d
    /* renamed from: b */
    public void mo835b() {
        T t = this.f2024f;
        if (t != null) {
            try {
                mo833c(t);
            } catch (IOException unused) {
            }
        }
    }

    /* renamed from: c */
    public abstract void mo833c(T t);

    @Override // p005b.p143g.p144a.p147m.p148s.InterfaceC1590d
    public void cancel() {
    }

    @Override // p005b.p143g.p144a.p147m.p148s.InterfaceC1590d
    /* renamed from: d */
    public final void mo837d(@NonNull EnumC1556f enumC1556f, @NonNull InterfaceC1590d.a<? super T> aVar) {
        try {
            T mo834e = mo834e(this.f2022c, this.f2023e);
            this.f2024f = mo834e;
            aVar.mo840e(mo834e);
        } catch (FileNotFoundException e2) {
            Log.isLoggable("LocalUriFetcher", 3);
            aVar.mo839c(e2);
        }
    }

    /* renamed from: e */
    public abstract T mo834e(Uri uri, ContentResolver contentResolver);

    @Override // p005b.p143g.p144a.p147m.p148s.InterfaceC1590d
    @NonNull
    public EnumC1569a getDataSource() {
        return EnumC1569a.LOCAL;
    }
}
