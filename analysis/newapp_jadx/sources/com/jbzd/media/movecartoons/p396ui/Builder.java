package com.jbzd.media.movecartoons.p396ui;

import android.os.Bundle;
import androidx.fragment.app.Fragment;
import androidx.fragment.app.FragmentFactory;
import com.drake.brv.annotaion.DividerOrientation;
import com.jbzd.media.movecartoons.p396ui.index.home.child.VideoListActivity;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p403d.p404a.p405a.p407b.p408a.C4195m;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u00008\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0010\u000e\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u000b\n\u0002\b\u0003\n\u0002\u0010\b\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\f\u0018\u00002\u00020\u0001B\u000f\u0012\u0006\u0010\u001a\u001a\u00020\u0002¢\u0006\u0004\b!\u0010\"J\u0015\u0010\u0003\u001a\u00020\u00002\u0006\u0010\u0003\u001a\u00020\u0002¢\u0006\u0004\b\u0003\u0010\u0004J\u0015\u0010\u0006\u001a\u00020\u00002\u0006\u0010\u0006\u001a\u00020\u0005¢\u0006\u0004\b\u0006\u0010\u0007J\u0015\u0010\n\u001a\u00020\u00002\u0006\u0010\t\u001a\u00020\b¢\u0006\u0004\b\n\u0010\u000bJ\u0015\u0010\r\u001a\u00020\u00002\u0006\u0010\r\u001a\u00020\f¢\u0006\u0004\b\r\u0010\u000eJ\u0015\u0010\u000f\u001a\u00020\u00002\u0006\u0010\u000f\u001a\u00020\f¢\u0006\u0004\b\u000f\u0010\u000eJ\u0015\u0010\u0011\u001a\u00020\u00002\u0006\u0010\u0010\u001a\u00020\f¢\u0006\u0004\b\u0011\u0010\u000eJ\u0015\u0010\u0014\u001a\u00020\u00002\u0006\u0010\u0013\u001a\u00020\u0012¢\u0006\u0004\b\u0014\u0010\u0015J\u0015\u0010\u0016\u001a\u00020\u00002\u0006\u0010\u0016\u001a\u00020\f¢\u0006\u0004\b\u0016\u0010\u000eJ\r\u0010\u0018\u001a\u00020\u0017¢\u0006\u0004\b\u0018\u0010\u0019R\u0016\u0010\u001a\u001a\u00020\u00028\u0002@\u0002X\u0082\u0004¢\u0006\u0006\n\u0004\b\u001a\u0010\u001bR\u0016\u0010\u0010\u001a\u00020\f8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b\u0010\u0010\u001cR\u0016\u0010\u0006\u001a\u00020\u00058\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b\u0006\u0010\u001dR\u0016\u0010\u0003\u001a\u00020\u00028\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b\u0003\u0010\u001bR\u0016\u0010\r\u001a\u00020\f8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b\r\u0010\u001cR\u0016\u0010\u000f\u001a\u00020\f8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b\u000f\u0010\u001cR\u0018\u0010\u001e\u001a\u0004\u0018\u00010\u00128\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b\u001e\u0010\u001fR\u0016\u0010\t\u001a\u00020\b8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b\t\u0010 R\u0016\u0010\u0016\u001a\u00020\f8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b\u0016\u0010\u001c¨\u0006#"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/Builder;", "", "", "requestUrl", "(Ljava/lang/String;)Lcom/jbzd/media/movecartoons/ui/Builder;", "Lb/i/a/h/a;", "orientation", "(Lb/i/a/h/a;)Lcom/jbzd/media/movecartoons/ui/Builder;", "", "reverseLayout", "isReverseLayout", "(Z)Lcom/jbzd/media/movecartoons/ui/Builder;", "", "spanCount", "(I)Lcom/jbzd/media/movecartoons/ui/Builder;", "dividerSpace", "dividerRes", "divider", "Landroid/os/Bundle;", "bundle", VideoListActivity.KEY_PARAMS, "(Landroid/os/Bundle;)Lcom/jbzd/media/movecartoons/ui/Builder;", "margin", "Landroidx/fragment/app/Fragment;", "build", "()Landroidx/fragment/app/Fragment;", "name", "Ljava/lang/String;", "I", "Lb/i/a/h/a;", "extra", "Landroid/os/Bundle;", "Z", "<init>", "(Ljava/lang/String;)V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class Builder {
    private int dividerRes;
    private int dividerSpace;

    @Nullable
    private Bundle extra;
    private int margin;

    @NotNull
    private final String name;

    @NotNull
    private DividerOrientation orientation;

    @NotNull
    private String requestUrl;
    private boolean reverseLayout;
    private int spanCount;

    public Builder(@NotNull String name) {
        Intrinsics.checkNotNullParameter(name, "name");
        this.name = name;
        this.requestUrl = "";
        this.orientation = DividerOrientation.VERTICAL;
        this.spanCount = 1;
        this.dividerRes = -1;
    }

    @NotNull
    public final Fragment build() {
        Fragment newInstance = FragmentFactory.loadFragmentClass(C4195m.m4792Y().getClassLoader(), this.name).getConstructor(new Class[0]).newInstance(new Object[0]);
        Fragment fragment = newInstance;
        Bundle bundle = new Bundle();
        bundle.putString(BaseListFragment.KEY_REQUEST_URL, this.requestUrl);
        bundle.putSerializable(BaseListFragment.KEY_ORIENTATION, this.orientation);
        bundle.putBoolean(BaseListFragment.KEY_REVERSE_LAYOUT, this.reverseLayout);
        bundle.putInt(BaseListFragment.KEY_SPAN_COUNT, this.spanCount);
        bundle.putInt(BaseListFragment.KEY_DIVIDER_SPACE, this.dividerSpace);
        bundle.putInt(BaseListFragment.KEY_DIVIDER_RES, this.dividerRes);
        bundle.putInt(BaseListFragment.KEY_MARGIN, this.margin);
        Bundle bundle2 = this.extra;
        if (bundle2 != null) {
            bundle.putBundle(BaseListFragment.KEY_EXTRA, bundle2);
        }
        Unit unit = Unit.INSTANCE;
        fragment.setArguments(bundle);
        Intrinsics.checkNotNullExpressionValue(newInstance, "loadFragmentClass(Utils.getApp().classLoader, name)\n            .getConstructor().newInstance().apply {\n                arguments = Bundle().apply {\n                    putString(BaseListFragment.KEY_REQUEST_URL, requestUrl)\n                    putSerializable(BaseListFragment.KEY_ORIENTATION, orientation)\n                    putBoolean(BaseListFragment.KEY_REVERSE_LAYOUT, reverseLayout)\n                    putInt(BaseListFragment.KEY_SPAN_COUNT, spanCount)\n                    putInt(BaseListFragment.KEY_DIVIDER_SPACE, dividerSpace)\n                    putInt(BaseListFragment.KEY_DIVIDER_RES, dividerRes)\n                    putInt(BaseListFragment.KEY_MARGIN, margin)\n                    extra?.let {\n                        putBundle(BaseListFragment.KEY_EXTRA, it)\n                    }\n                }\n            }");
        return fragment;
    }

    @NotNull
    public final Builder divider(int dividerRes) {
        this.dividerRes = dividerRes;
        return this;
    }

    @NotNull
    public final Builder dividerSpace(int dividerSpace) {
        this.dividerSpace = dividerSpace;
        return this;
    }

    @NotNull
    public final Builder isReverseLayout(boolean reverseLayout) {
        this.reverseLayout = reverseLayout;
        return this;
    }

    @NotNull
    public final Builder margin(int margin) {
        this.margin = margin;
        return this;
    }

    @NotNull
    public final Builder orientation(@NotNull DividerOrientation orientation) {
        Intrinsics.checkNotNullParameter(orientation, "orientation");
        this.orientation = orientation;
        return this;
    }

    @NotNull
    public final Builder params(@NotNull Bundle bundle) {
        Intrinsics.checkNotNullParameter(bundle, "bundle");
        this.extra = bundle;
        return this;
    }

    @NotNull
    public final Builder requestUrl(@NotNull String requestUrl) {
        Intrinsics.checkNotNullParameter(requestUrl, "requestUrl");
        this.requestUrl = requestUrl;
        return this;
    }

    @NotNull
    public final Builder spanCount(int spanCount) {
        this.spanCount = spanCount;
        return this;
    }
}
