package androidx.core.graphics;

import android.graphics.Point;
import android.graphics.PointF;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u0018\n\u0002\u0018\u0002\n\u0002\u0010\b\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\u0010\u0007\n\u0002\b\u0011\u001a\u0014\u0010\u0002\u001a\u00020\u0001*\u00020\u0000H\u0086\n¢\u0006\u0004\b\u0002\u0010\u0003\u001a\u0014\u0010\u0004\u001a\u00020\u0001*\u00020\u0000H\u0086\n¢\u0006\u0004\b\u0004\u0010\u0003\u001a\u0014\u0010\u0002\u001a\u00020\u0006*\u00020\u0005H\u0086\n¢\u0006\u0004\b\u0002\u0010\u0007\u001a\u0014\u0010\u0004\u001a\u00020\u0006*\u00020\u0005H\u0086\n¢\u0006\u0004\b\u0004\u0010\u0007\u001a\u001c\u0010\t\u001a\u00020\u0000*\u00020\u00002\u0006\u0010\b\u001a\u00020\u0000H\u0086\n¢\u0006\u0004\b\t\u0010\n\u001a\u001c\u0010\t\u001a\u00020\u0005*\u00020\u00052\u0006\u0010\b\u001a\u00020\u0005H\u0086\n¢\u0006\u0004\b\t\u0010\u000b\u001a\u001c\u0010\t\u001a\u00020\u0000*\u00020\u00002\u0006\u0010\f\u001a\u00020\u0001H\u0086\n¢\u0006\u0004\b\t\u0010\r\u001a\u001c\u0010\t\u001a\u00020\u0005*\u00020\u00052\u0006\u0010\f\u001a\u00020\u0006H\u0086\n¢\u0006\u0004\b\t\u0010\u000e\u001a\u001c\u0010\u000f\u001a\u00020\u0000*\u00020\u00002\u0006\u0010\b\u001a\u00020\u0000H\u0086\n¢\u0006\u0004\b\u000f\u0010\n\u001a\u001c\u0010\u000f\u001a\u00020\u0005*\u00020\u00052\u0006\u0010\b\u001a\u00020\u0005H\u0086\n¢\u0006\u0004\b\u000f\u0010\u000b\u001a\u001c\u0010\u000f\u001a\u00020\u0000*\u00020\u00002\u0006\u0010\f\u001a\u00020\u0001H\u0086\n¢\u0006\u0004\b\u000f\u0010\r\u001a\u001c\u0010\u000f\u001a\u00020\u0005*\u00020\u00052\u0006\u0010\f\u001a\u00020\u0006H\u0086\n¢\u0006\u0004\b\u000f\u0010\u000e\u001a\u0014\u0010\u0010\u001a\u00020\u0000*\u00020\u0000H\u0086\n¢\u0006\u0004\b\u0010\u0010\u0011\u001a\u0014\u0010\u0010\u001a\u00020\u0005*\u00020\u0005H\u0086\n¢\u0006\u0004\b\u0010\u0010\u0012\u001a\u0014\u0010\u0013\u001a\u00020\u0005*\u00020\u0000H\u0086\b¢\u0006\u0004\b\u0013\u0010\u0014\u001a\u0014\u0010\u0015\u001a\u00020\u0000*\u00020\u0005H\u0086\b¢\u0006\u0004\b\u0015\u0010\u0016¨\u0006\u0017"}, m5311d2 = {"Landroid/graphics/Point;", "", "component1", "(Landroid/graphics/Point;)I", "component2", "Landroid/graphics/PointF;", "", "(Landroid/graphics/PointF;)F", "p", "plus", "(Landroid/graphics/Point;Landroid/graphics/Point;)Landroid/graphics/Point;", "(Landroid/graphics/PointF;Landroid/graphics/PointF;)Landroid/graphics/PointF;", "xy", "(Landroid/graphics/Point;I)Landroid/graphics/Point;", "(Landroid/graphics/PointF;F)Landroid/graphics/PointF;", "minus", "unaryMinus", "(Landroid/graphics/Point;)Landroid/graphics/Point;", "(Landroid/graphics/PointF;)Landroid/graphics/PointF;", "toPointF", "(Landroid/graphics/Point;)Landroid/graphics/PointF;", "toPoint", "(Landroid/graphics/PointF;)Landroid/graphics/Point;", "core-ktx_release"}, m5312k = 2, m5313mv = {1, 5, 1})
/* loaded from: classes.dex */
public final class PointKt {
    public static final int component1(@NotNull Point point) {
        Intrinsics.checkNotNullParameter(point, "<this>");
        return point.x;
    }

    public static final int component2(@NotNull Point point) {
        Intrinsics.checkNotNullParameter(point, "<this>");
        return point.y;
    }

    @NotNull
    public static final Point minus(@NotNull Point point, @NotNull Point p) {
        Intrinsics.checkNotNullParameter(point, "<this>");
        Intrinsics.checkNotNullParameter(p, "p");
        Point point2 = new Point(point.x, point.y);
        point2.offset(-p.x, -p.y);
        return point2;
    }

    @NotNull
    public static final Point plus(@NotNull Point point, @NotNull Point p) {
        Intrinsics.checkNotNullParameter(point, "<this>");
        Intrinsics.checkNotNullParameter(p, "p");
        Point point2 = new Point(point.x, point.y);
        point2.offset(p.x, p.y);
        return point2;
    }

    @NotNull
    public static final Point toPoint(@NotNull PointF pointF) {
        Intrinsics.checkNotNullParameter(pointF, "<this>");
        return new Point((int) pointF.x, (int) pointF.y);
    }

    @NotNull
    public static final PointF toPointF(@NotNull Point point) {
        Intrinsics.checkNotNullParameter(point, "<this>");
        return new PointF(point);
    }

    @NotNull
    public static final Point unaryMinus(@NotNull Point point) {
        Intrinsics.checkNotNullParameter(point, "<this>");
        return new Point(-point.x, -point.y);
    }

    public static final float component1(@NotNull PointF pointF) {
        Intrinsics.checkNotNullParameter(pointF, "<this>");
        return pointF.x;
    }

    public static final float component2(@NotNull PointF pointF) {
        Intrinsics.checkNotNullParameter(pointF, "<this>");
        return pointF.y;
    }

    @NotNull
    public static final PointF unaryMinus(@NotNull PointF pointF) {
        Intrinsics.checkNotNullParameter(pointF, "<this>");
        return new PointF(-pointF.x, -pointF.y);
    }

    @NotNull
    public static final PointF minus(@NotNull PointF pointF, @NotNull PointF p) {
        Intrinsics.checkNotNullParameter(pointF, "<this>");
        Intrinsics.checkNotNullParameter(p, "p");
        PointF pointF2 = new PointF(pointF.x, pointF.y);
        pointF2.offset(-p.x, -p.y);
        return pointF2;
    }

    @NotNull
    public static final PointF plus(@NotNull PointF pointF, @NotNull PointF p) {
        Intrinsics.checkNotNullParameter(pointF, "<this>");
        Intrinsics.checkNotNullParameter(p, "p");
        PointF pointF2 = new PointF(pointF.x, pointF.y);
        pointF2.offset(p.x, p.y);
        return pointF2;
    }

    @NotNull
    public static final Point minus(@NotNull Point point, int i2) {
        Intrinsics.checkNotNullParameter(point, "<this>");
        Point point2 = new Point(point.x, point.y);
        int i3 = -i2;
        point2.offset(i3, i3);
        return point2;
    }

    @NotNull
    public static final Point plus(@NotNull Point point, int i2) {
        Intrinsics.checkNotNullParameter(point, "<this>");
        Point point2 = new Point(point.x, point.y);
        point2.offset(i2, i2);
        return point2;
    }

    @NotNull
    public static final PointF minus(@NotNull PointF pointF, float f2) {
        Intrinsics.checkNotNullParameter(pointF, "<this>");
        PointF pointF2 = new PointF(pointF.x, pointF.y);
        float f3 = -f2;
        pointF2.offset(f3, f3);
        return pointF2;
    }

    @NotNull
    public static final PointF plus(@NotNull PointF pointF, float f2) {
        Intrinsics.checkNotNullParameter(pointF, "<this>");
        PointF pointF2 = new PointF(pointF.x, pointF.y);
        pointF2.offset(f2, f2);
        return pointF2;
    }
}
