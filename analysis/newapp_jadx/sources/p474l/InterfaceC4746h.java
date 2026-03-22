package p474l;

import java.io.InputStream;
import java.nio.channels.ReadableByteChannel;
import java.nio.charset.Charset;
import org.jetbrains.annotations.NotNull;

/* renamed from: l.h */
/* loaded from: classes3.dex */
public interface InterfaceC4746h extends InterfaceC4764z, ReadableByteChannel {
    /* renamed from: A */
    boolean mo5350A(long j2);

    @NotNull
    /* renamed from: B */
    String mo5351B();

    @NotNull
    /* renamed from: F */
    byte[] mo5355F(long j2);

    /* renamed from: K */
    long mo5359K(@NotNull InterfaceC4762x interfaceC4762x);

    /* renamed from: M */
    void mo5360M(long j2);

    /* renamed from: Q */
    long mo5363Q();

    @NotNull
    /* renamed from: R */
    InputStream mo5364R();

    /* renamed from: T */
    int mo5366T(@NotNull C4755q c4755q);

    @NotNull
    /* renamed from: f */
    C4747i mo5380f(long j2);

    @NotNull
    C4744f getBuffer();

    @NotNull
    /* renamed from: l */
    byte[] mo5386l();

    /* renamed from: m */
    boolean mo5387m();

    @NotNull
    /* renamed from: r */
    String mo5390r(long j2);

    byte readByte();

    int readInt();

    short readShort();

    void skip(long j2);

    @NotNull
    /* renamed from: w */
    String mo5395w(@NotNull Charset charset);
}
