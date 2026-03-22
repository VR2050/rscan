package com.jbzd.media.movecartoons.view.video;

import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p131d.p132a.p133a.C1499a;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000(\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0010\u0007\n\u0002\b\u0002\n\u0002\u0010\u000e\n\u0002\b\u0007\n\u0002\u0010\b\n\u0002\b\u0003\n\u0002\u0010\u000b\n\u0002\b\t\b\u0086\b\u0018\u00002\u00020\u0001B\u0017\u0012\u0006\u0010\b\u001a\u00020\u0002\u0012\u0006\u0010\t\u001a\u00020\u0005¢\u0006\u0004\b\u0018\u0010\u0019J\u0010\u0010\u0003\u001a\u00020\u0002HÆ\u0003¢\u0006\u0004\b\u0003\u0010\u0004J\u0010\u0010\u0006\u001a\u00020\u0005HÆ\u0003¢\u0006\u0004\b\u0006\u0010\u0007J$\u0010\n\u001a\u00020\u00002\b\b\u0002\u0010\b\u001a\u00020\u00022\b\b\u0002\u0010\t\u001a\u00020\u0005HÆ\u0001¢\u0006\u0004\b\n\u0010\u000bJ\u0010\u0010\f\u001a\u00020\u0005HÖ\u0001¢\u0006\u0004\b\f\u0010\u0007J\u0010\u0010\u000e\u001a\u00020\rHÖ\u0001¢\u0006\u0004\b\u000e\u0010\u000fJ\u001a\u0010\u0012\u001a\u00020\u00112\b\u0010\u0010\u001a\u0004\u0018\u00010\u0001HÖ\u0003¢\u0006\u0004\b\u0012\u0010\u0013R\u0019\u0010\b\u001a\u00020\u00028\u0006@\u0006¢\u0006\f\n\u0004\b\b\u0010\u0014\u001a\u0004\b\u0015\u0010\u0004R\u0019\u0010\t\u001a\u00020\u00058\u0006@\u0006¢\u0006\f\n\u0004\b\t\u0010\u0016\u001a\u0004\b\u0017\u0010\u0007¨\u0006\u001a"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/view/video/Speed;", "", "", "component1", "()F", "", "component2", "()Ljava/lang/String;", "speed", "name", "copy", "(FLjava/lang/String;)Lcom/jbzd/media/movecartoons/view/video/Speed;", "toString", "", "hashCode", "()I", "other", "", "equals", "(Ljava/lang/Object;)Z", "F", "getSpeed", "Ljava/lang/String;", "getName", "<init>", "(FLjava/lang/String;)V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final /* data */ class Speed {

    @NotNull
    private final String name;
    private final float speed;

    public Speed(float f2, @NotNull String name) {
        Intrinsics.checkNotNullParameter(name, "name");
        this.speed = f2;
        this.name = name;
    }

    public static /* synthetic */ Speed copy$default(Speed speed, float f2, String str, int i2, Object obj) {
        if ((i2 & 1) != 0) {
            f2 = speed.speed;
        }
        if ((i2 & 2) != 0) {
            str = speed.name;
        }
        return speed.copy(f2, str);
    }

    /* renamed from: component1, reason: from getter */
    public final float getSpeed() {
        return this.speed;
    }

    @NotNull
    /* renamed from: component2, reason: from getter */
    public final String getName() {
        return this.name;
    }

    @NotNull
    public final Speed copy(float speed, @NotNull String name) {
        Intrinsics.checkNotNullParameter(name, "name");
        return new Speed(speed, name);
    }

    public boolean equals(@Nullable Object other) {
        if (this == other) {
            return true;
        }
        if (!(other instanceof Speed)) {
            return false;
        }
        Speed speed = (Speed) other;
        return Intrinsics.areEqual((Object) Float.valueOf(this.speed), (Object) Float.valueOf(speed.speed)) && Intrinsics.areEqual(this.name, speed.name);
    }

    @NotNull
    public final String getName() {
        return this.name;
    }

    public final float getSpeed() {
        return this.speed;
    }

    public int hashCode() {
        return this.name.hashCode() + (Float.floatToIntBits(this.speed) * 31);
    }

    @NotNull
    public String toString() {
        StringBuilder m586H = C1499a.m586H("Speed(speed=");
        m586H.append(this.speed);
        m586H.append(", name=");
        return C1499a.m581C(m586H, this.name, ')');
    }
}
