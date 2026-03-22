package p474l;

import java.nio.channels.WritableByteChannel;
import org.jetbrains.annotations.NotNull;

/* renamed from: l.g */
/* loaded from: classes3.dex */
public interface InterfaceC4745g extends InterfaceC4762x, WritableByteChannel {
    @NotNull
    /* renamed from: G */
    InterfaceC4745g mo5356G(@NotNull byte[] bArr);

    @NotNull
    /* renamed from: H */
    InterfaceC4745g mo5357H(@NotNull C4747i c4747i);

    @NotNull
    /* renamed from: N */
    InterfaceC4745g mo5361N(long j2);

    @NotNull
    /* renamed from: a */
    InterfaceC4745g mo5373a(@NotNull byte[] bArr, int i2, int i3);

    @Override // p474l.InterfaceC4762x, java.io.Flushable
    void flush();

    @NotNull
    C4744f getBuffer();

    @NotNull
    /* renamed from: h */
    InterfaceC4745g mo5383h(int i2);

    @NotNull
    /* renamed from: j */
    InterfaceC4745g mo5385j(int i2);

    @NotNull
    /* renamed from: n */
    InterfaceC4745g mo5388n(int i2);

    @NotNull
    /* renamed from: p */
    InterfaceC4745g mo5389p();

    @NotNull
    /* renamed from: u */
    InterfaceC4745g mo5393u(@NotNull String str);

    /* renamed from: y */
    long mo5396y(@NotNull InterfaceC4764z interfaceC4764z);

    @NotNull
    /* renamed from: z */
    InterfaceC4745g mo5397z(long j2);
}
