package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.appcompat.widget.LinearLayoutCompat;
import androidx.viewbinding.ViewBinding;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class DialogRetrieveLayoutBinding implements ViewBinding {

    @NonNull
    public final TextView btnCancel;

    @NonNull
    private final LinearLayoutCompat rootView;

    @NonNull
    public final TextView txtScan;

    @NonNull
    public final TextView txtUpload;

    private DialogRetrieveLayoutBinding(@NonNull LinearLayoutCompat linearLayoutCompat, @NonNull TextView textView, @NonNull TextView textView2, @NonNull TextView textView3) {
        this.rootView = linearLayoutCompat;
        this.btnCancel = textView;
        this.txtScan = textView2;
        this.txtUpload = textView3;
    }

    @NonNull
    public static DialogRetrieveLayoutBinding bind(@NonNull View view) {
        int i2 = R.id.btn_cancel;
        TextView textView = (TextView) view.findViewById(R.id.btn_cancel);
        if (textView != null) {
            i2 = R.id.txt_scan;
            TextView textView2 = (TextView) view.findViewById(R.id.txt_scan);
            if (textView2 != null) {
                i2 = R.id.txt_upload;
                TextView textView3 = (TextView) view.findViewById(R.id.txt_upload);
                if (textView3 != null) {
                    return new DialogRetrieveLayoutBinding((LinearLayoutCompat) view, textView, textView2, textView3);
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static DialogRetrieveLayoutBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static DialogRetrieveLayoutBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.dialog_retrieve_layout, viewGroup, false);
        if (z) {
            viewGroup.addView(inflate);
        }
        return bind(inflate);
    }

    @Override // androidx.viewbinding.ViewBinding
    @NonNull
    public LinearLayoutCompat getRoot() {
        return this.rootView;
    }
}
