package p005b.p143g.p144a.p147m.p148s;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import p005b.p143g.p144a.EnumC1556f;
import p005b.p143g.p144a.p147m.EnumC1569a;

/* renamed from: b.g.a.m.s.d */
/* loaded from: classes.dex */
public interface InterfaceC1590d<T> {

    /* renamed from: b.g.a.m.s.d$a */
    public interface a<T> {
        /* renamed from: c */
        void mo839c(@NonNull Exception exc);

        /* renamed from: e */
        void mo840e(@Nullable T t);
    }

    @NonNull
    /* renamed from: a */
    Class<T> mo832a();

    /* renamed from: b */
    void mo835b();

    void cancel();

    /* renamed from: d */
    void mo837d(@NonNull EnumC1556f enumC1556f, @NonNull a<? super T> aVar);

    @NonNull
    EnumC1569a getDataSource();
}
