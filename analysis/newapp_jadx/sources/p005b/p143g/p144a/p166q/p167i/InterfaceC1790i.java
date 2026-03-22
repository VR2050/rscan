package p005b.p143g.p144a.p166q.p167i;

import android.graphics.drawable.Drawable;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import p005b.p143g.p144a.p163n.InterfaceC1755i;
import p005b.p143g.p144a.p166q.InterfaceC1775b;
import p005b.p143g.p144a.p166q.p168j.InterfaceC1793b;

/* renamed from: b.g.a.q.i.i */
/* loaded from: classes.dex */
public interface InterfaceC1790i<R> extends InterfaceC1755i {
    @Nullable
    InterfaceC1775b getRequest();

    void getSize(@NonNull InterfaceC1789h interfaceC1789h);

    void onLoadCleared(@Nullable Drawable drawable);

    void onLoadFailed(@Nullable Drawable drawable);

    void onLoadStarted(@Nullable Drawable drawable);

    void onResourceReady(@NonNull R r, @Nullable InterfaceC1793b<? super R> interfaceC1793b);

    void removeCallback(@NonNull InterfaceC1789h interfaceC1789h);

    void setRequest(@Nullable InterfaceC1775b interfaceC1775b);
}
