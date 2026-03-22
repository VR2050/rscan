package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.viewbinding.ViewBinding;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class DialogHistoryBottomBinding implements ViewBinding {

    @NonNull
    public final TextView btn1;

    @NonNull
    public final TextView btn2;

    @NonNull
    public final View outsideView;

    @NonNull
    private final LinearLayout rootView;

    private DialogHistoryBottomBinding(@NonNull LinearLayout linearLayout, @NonNull TextView textView, @NonNull TextView textView2, @NonNull View view) {
        this.rootView = linearLayout;
        this.btn1 = textView;
        this.btn2 = textView2;
        this.outsideView = view;
    }

    @NonNull
    public static DialogHistoryBottomBinding bind(@NonNull View view) {
        int i2 = R.id.btn1;
        TextView textView = (TextView) view.findViewById(R.id.btn1);
        if (textView != null) {
            i2 = R.id.btn2;
            TextView textView2 = (TextView) view.findViewById(R.id.btn2);
            if (textView2 != null) {
                i2 = R.id.outside_view;
                View findViewById = view.findViewById(R.id.outside_view);
                if (findViewById != null) {
                    return new DialogHistoryBottomBinding((LinearLayout) view, textView, textView2, findViewById);
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static DialogHistoryBottomBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static DialogHistoryBottomBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.dialog_history_bottom, viewGroup, false);
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
