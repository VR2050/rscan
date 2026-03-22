package p458k.p459p0.p460d;

import java.io.IOException;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import p474l.AbstractC4748j;
import p474l.C4744f;
import p474l.InterfaceC4762x;

/* renamed from: k.p0.d.f */
/* loaded from: classes3.dex */
public class C4407f extends AbstractC4748j {

    /* renamed from: e */
    public boolean f11614e;

    /* renamed from: f */
    @NotNull
    public final Function1<IOException, Unit> f11615f;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    /* JADX WARN: Multi-variable type inference failed */
    public C4407f(@NotNull InterfaceC4762x delegate, @NotNull Function1<? super IOException, Unit> onException) {
        super(delegate);
        Intrinsics.checkParameterIsNotNull(delegate, "delegate");
        Intrinsics.checkParameterIsNotNull(onException, "onException");
        this.f11615f = onException;
    }

    @Override // p474l.AbstractC4748j, p474l.InterfaceC4762x, java.io.Closeable, java.lang.AutoCloseable
    public void close() {
        if (this.f11614e) {
            return;
        }
        try {
            super.close();
        } catch (IOException e2) {
            this.f11614e = true;
            this.f11615f.invoke(e2);
        }
    }

    @Override // p474l.AbstractC4748j, p474l.InterfaceC4762x, java.io.Flushable
    public void flush() {
        if (this.f11614e) {
            return;
        }
        try {
            this.f12140c.flush();
        } catch (IOException e2) {
            this.f11614e = true;
            this.f11615f.invoke(e2);
        }
    }

    @Override // p474l.AbstractC4748j, p474l.InterfaceC4762x
    /* renamed from: x */
    public void mo4923x(@NotNull C4744f source, long j2) {
        Intrinsics.checkParameterIsNotNull(source, "source");
        if (this.f11614e) {
            source.skip(j2);
            return;
        }
        try {
            super.mo4923x(source, j2);
        } catch (IOException e2) {
            this.f11614e = true;
            this.f11615f.invoke(e2);
        }
    }
}
