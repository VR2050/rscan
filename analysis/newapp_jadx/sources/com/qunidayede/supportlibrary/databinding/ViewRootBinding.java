package com.qunidayede.supportlibrary.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.ViewStub;
import android.widget.FrameLayout;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.viewbinding.ViewBinding;
import com.qunidayede.supportlibrary.R$id;
import com.qunidayede.supportlibrary.R$layout;

/* loaded from: classes2.dex */
public final class ViewRootBinding implements ViewBinding {

    @NonNull
    public final FrameLayout layoutBody;

    @NonNull
    public final FrameLayout layoutRoot;

    @NonNull
    public final ViewStub loadingViewStub;

    @NonNull
    private final FrameLayout rootView;

    @NonNull
    public final ViewStub titleBarViewStub;

    private ViewRootBinding(@NonNull FrameLayout frameLayout, @NonNull FrameLayout frameLayout2, @NonNull FrameLayout frameLayout3, @NonNull ViewStub viewStub, @NonNull ViewStub viewStub2) {
        this.rootView = frameLayout;
        this.layoutBody = frameLayout2;
        this.layoutRoot = frameLayout3;
        this.loadingViewStub = viewStub;
        this.titleBarViewStub = viewStub2;
    }

    @NonNull
    public static ViewRootBinding bind(@NonNull View view) {
        int i2 = R$id.layout_body;
        FrameLayout frameLayout = (FrameLayout) view.findViewById(i2);
        if (frameLayout != null) {
            FrameLayout frameLayout2 = (FrameLayout) view;
            i2 = R$id.loading_view_stub;
            ViewStub viewStub = (ViewStub) view.findViewById(i2);
            if (viewStub != null) {
                i2 = R$id.title_bar_view_stub;
                ViewStub viewStub2 = (ViewStub) view.findViewById(i2);
                if (viewStub2 != null) {
                    return new ViewRootBinding(frameLayout2, frameLayout, frameLayout2, viewStub, viewStub2);
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static ViewRootBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static ViewRootBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R$layout.view_root, viewGroup, false);
        if (z) {
            viewGroup.addView(inflate);
        }
        return bind(inflate);
    }

    @Override // androidx.viewbinding.ViewBinding
    @NonNull
    public FrameLayout getRoot() {
        return this.rootView;
    }
}
