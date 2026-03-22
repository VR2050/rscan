package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.webkit.WebView;
import android.widget.LinearLayout;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.viewbinding.ViewBinding;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class FragmentAiAreaWebBinding implements ViewBinding {

    @NonNull
    public final LinearLayout llWebTop;

    @NonNull
    private final LinearLayout rootView;

    @NonNull
    public final WebView webView;

    private FragmentAiAreaWebBinding(@NonNull LinearLayout linearLayout, @NonNull LinearLayout linearLayout2, @NonNull WebView webView) {
        this.rootView = linearLayout;
        this.llWebTop = linearLayout2;
        this.webView = webView;
    }

    @NonNull
    public static FragmentAiAreaWebBinding bind(@NonNull View view) {
        LinearLayout linearLayout = (LinearLayout) view;
        WebView webView = (WebView) view.findViewById(R.id.webView);
        if (webView != null) {
            return new FragmentAiAreaWebBinding((LinearLayout) view, linearLayout, webView);
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(R.id.webView)));
    }

    @NonNull
    public static FragmentAiAreaWebBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static FragmentAiAreaWebBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.fragment_ai_area_web, viewGroup, false);
        if (z) {
            viewGroup.addView(inflate);
        }
        return bind(inflate);
    }

    @Override // androidx.viewbinding.ViewBinding
    @NonNull
    public LinearLayout getRoot() {
        return this.rootView;
    }
}
