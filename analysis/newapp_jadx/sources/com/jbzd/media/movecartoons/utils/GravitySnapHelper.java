package com.jbzd.media.movecartoons.utils;

import android.annotation.SuppressLint;
import android.view.View;
import androidx.annotation.NonNull;
import androidx.core.view.GravityCompat;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.LinearSnapHelper;
import androidx.recyclerview.widget.OrientationHelper;
import androidx.recyclerview.widget.RecyclerView;

/* loaded from: classes2.dex */
public class GravitySnapHelper extends LinearSnapHelper {

    /* renamed from: a */
    public OrientationHelper f10119a;

    /* renamed from: b */
    public OrientationHelper f10120b;

    /* renamed from: c */
    public int f10121c;

    @SuppressLint({"RtlHardcoded"})
    public GravitySnapHelper(int i2) {
        this.f10121c = i2;
        if (i2 == 3) {
            this.f10121c = GravityCompat.START;
        } else if (i2 == 5) {
            this.f10121c = GravityCompat.END;
        }
    }

    /* renamed from: a */
    public final int m4495a(View view, OrientationHelper orientationHelper) {
        return orientationHelper.getDecoratedEnd(view) - orientationHelper.getEndAfterPadding();
    }

    /* renamed from: b */
    public final View m4496b(RecyclerView.LayoutManager layoutManager, OrientationHelper orientationHelper) {
        if (!(layoutManager instanceof LinearLayoutManager)) {
            return super.findSnapView(layoutManager);
        }
        int findLastVisibleItemPosition = ((LinearLayoutManager) layoutManager).findLastVisibleItemPosition();
        if (findLastVisibleItemPosition == -1) {
            return null;
        }
        View findViewByPosition = layoutManager.findViewByPosition(findLastVisibleItemPosition);
        if ((orientationHelper.getDecoratedMeasurement(findViewByPosition) / 2) + orientationHelper.getDecoratedStart(findViewByPosition) <= orientationHelper.getTotalSpace()) {
            return findViewByPosition;
        }
        if (((LinearLayoutManager) layoutManager).findFirstCompletelyVisibleItemPosition() == 0) {
            return null;
        }
        return layoutManager.findViewByPosition(findLastVisibleItemPosition - 1);
    }

    /* renamed from: c */
    public final View m4497c(RecyclerView.LayoutManager layoutManager, OrientationHelper orientationHelper) {
        if (!(layoutManager instanceof LinearLayoutManager)) {
            return super.findSnapView(layoutManager);
        }
        int findFirstVisibleItemPosition = ((LinearLayoutManager) layoutManager).findFirstVisibleItemPosition();
        if (findFirstVisibleItemPosition == -1) {
            return null;
        }
        View findViewByPosition = layoutManager.findViewByPosition(findFirstVisibleItemPosition);
        if (orientationHelper.getDecoratedEnd(findViewByPosition) >= orientationHelper.getDecoratedMeasurement(findViewByPosition) / 2 && orientationHelper.getDecoratedEnd(findViewByPosition) > 0) {
            return findViewByPosition;
        }
        if (((LinearLayoutManager) layoutManager).findLastCompletelyVisibleItemPosition() == layoutManager.getItemCount() - 1) {
            return null;
        }
        return layoutManager.findViewByPosition(findFirstVisibleItemPosition + 1);
    }

    @Override // androidx.recyclerview.widget.LinearSnapHelper, androidx.recyclerview.widget.SnapHelper
    public int[] calculateDistanceToFinalSnap(@NonNull RecyclerView.LayoutManager layoutManager, @NonNull View view) {
        int[] iArr = new int[2];
        if (!layoutManager.canScrollHorizontally()) {
            iArr[0] = 0;
        } else if (this.f10121c == 8388611) {
            if (this.f10120b == null) {
                this.f10120b = OrientationHelper.createHorizontalHelper(layoutManager);
            }
            OrientationHelper orientationHelper = this.f10120b;
            iArr[0] = orientationHelper.getDecoratedStart(view) - orientationHelper.getStartAfterPadding();
        } else {
            if (this.f10120b == null) {
                this.f10120b = OrientationHelper.createHorizontalHelper(layoutManager);
            }
            iArr[0] = m4495a(view, this.f10120b);
        }
        if (!layoutManager.canScrollVertically()) {
            iArr[1] = 0;
        } else if (this.f10121c == 48) {
            if (this.f10119a == null) {
                this.f10119a = OrientationHelper.createVerticalHelper(layoutManager);
            }
            OrientationHelper orientationHelper2 = this.f10119a;
            iArr[1] = orientationHelper2.getDecoratedStart(view) - orientationHelper2.getStartAfterPadding();
        } else {
            if (this.f10119a == null) {
                this.f10119a = OrientationHelper.createVerticalHelper(layoutManager);
            }
            iArr[1] = m4495a(view, this.f10119a);
        }
        return iArr;
    }

    @Override // androidx.recyclerview.widget.LinearSnapHelper, androidx.recyclerview.widget.SnapHelper
    public View findSnapView(RecyclerView.LayoutManager layoutManager) {
        if (layoutManager instanceof LinearLayoutManager) {
            int i2 = this.f10121c;
            if (i2 == 48) {
                if (this.f10119a == null) {
                    this.f10119a = OrientationHelper.createVerticalHelper(layoutManager);
                }
                return m4497c(layoutManager, this.f10119a);
            }
            if (i2 == 80) {
                if (this.f10119a == null) {
                    this.f10119a = OrientationHelper.createVerticalHelper(layoutManager);
                }
                return m4496b(layoutManager, this.f10119a);
            }
            if (i2 == 8388611) {
                if (this.f10120b == null) {
                    this.f10120b = OrientationHelper.createHorizontalHelper(layoutManager);
                }
                return m4497c(layoutManager, this.f10120b);
            }
            if (i2 == 8388613) {
                if (this.f10120b == null) {
                    this.f10120b = OrientationHelper.createHorizontalHelper(layoutManager);
                }
                return m4496b(layoutManager, this.f10120b);
            }
        }
        return super.findSnapView(layoutManager);
    }
}
