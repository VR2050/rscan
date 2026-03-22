package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.viewbinding.ViewBinding;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class DialogAlertDeepBinding implements ViewBinding {

    @NonNull
    public final TextView btn;

    @NonNull
    public final TextView btnAppStore;

    @NonNull
    public final LinearLayout layoutDarkwebBottom;

    @NonNull
    public final LinearLayout layoutDarkwebTop;

    @NonNull
    private final FrameLayout rootView;

    @NonNull
    public final TextView tvTips;

    private DialogAlertDeepBinding(@NonNull FrameLayout frameLayout, @NonNull TextView textView, @NonNull TextView textView2, @NonNull LinearLayout linearLayout, @NonNull LinearLayout linearLayout2, @NonNull TextView textView3) {
        this.rootView = frameLayout;
        this.btn = textView;
        this.btnAppStore = textView2;
        this.layoutDarkwebBottom = linearLayout;
        this.layoutDarkwebTop = linearLayout2;
        this.tvTips = textView3;
    }

    @NonNull
    public static DialogAlertDeepBinding bind(@NonNull View view) {
        int i2 = R.id.btn;
        TextView textView = (TextView) view.findViewById(R.id.btn);
        if (textView != null) {
            i2 = R.id.btnAppStore;
            TextView textView2 = (TextView) view.findViewById(R.id.btnAppStore);
            if (textView2 != null) {
                i2 = R.id.layout_darkweb_bottom;
                LinearLayout linearLayout = (LinearLayout) view.findViewById(R.id.layout_darkweb_bottom);
                if (linearLayout != null) {
                    i2 = R.id.layout_darkweb_top;
                    LinearLayout linearLayout2 = (LinearLayout) view.findViewById(R.id.layout_darkweb_top);
                    if (linearLayout2 != null) {
                        i2 = R.id.tvTips;
                        TextView textView3 = (TextView) view.findViewById(R.id.tvTips);
                        if (textView3 != null) {
                            return new DialogAlertDeepBinding((FrameLayout) view, textView, textView2, linearLayout, linearLayout2, textView3);
                        }
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static DialogAlertDeepBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static DialogAlertDeepBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.dialog_alert_deep, viewGroup, false);
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
