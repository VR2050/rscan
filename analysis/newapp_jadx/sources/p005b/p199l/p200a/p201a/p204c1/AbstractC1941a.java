package p005b.p199l.p200a.p201a.p204c1;

import com.alibaba.fastjson.asm.Label;

/* renamed from: b.l.a.a.c1.a */
/* loaded from: classes.dex */
public abstract class AbstractC1941a {
    private int flags;

    public final void addFlag(int i2) {
        this.flags = i2 | this.flags;
    }

    public void clear() {
        this.flags = 0;
    }

    public final void clearFlag(int i2) {
        this.flags = (~i2) & this.flags;
    }

    public final boolean getFlag(int i2) {
        return (this.flags & i2) == i2;
    }

    public final boolean hasSupplementalData() {
        return getFlag(Label.FORWARD_REFERENCE_TYPE_SHORT);
    }

    public final boolean isDecodeOnly() {
        return getFlag(Integer.MIN_VALUE);
    }

    public final boolean isEndOfStream() {
        return getFlag(4);
    }

    public final boolean isKeyFrame() {
        return getFlag(1);
    }

    public final void setFlags(int i2) {
        this.flags = i2;
    }
}
