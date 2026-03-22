package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.EditText;
import android.widget.ImageView;
import android.widget.LinearLayout;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.appcompat.widget.LinearLayoutCompat;
import androidx.recyclerview.widget.RecyclerView;
import androidx.viewbinding.ViewBinding;
import com.drake.brv.PageRefreshLayout;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class ChatDetailActBinding implements ViewBinding {

    @NonNull
    public final ImageView btnPic;

    @NonNull
    public final ImageView btnSend;

    @NonNull
    public final EditText edInput;

    @NonNull
    public final RecyclerView list;

    @NonNull
    public final LinearLayout llInput;

    @NonNull
    public final PageRefreshLayout pager;

    @NonNull
    private final LinearLayoutCompat rootView;

    private ChatDetailActBinding(@NonNull LinearLayoutCompat linearLayoutCompat, @NonNull ImageView imageView, @NonNull ImageView imageView2, @NonNull EditText editText, @NonNull RecyclerView recyclerView, @NonNull LinearLayout linearLayout, @NonNull PageRefreshLayout pageRefreshLayout) {
        this.rootView = linearLayoutCompat;
        this.btnPic = imageView;
        this.btnSend = imageView2;
        this.edInput = editText;
        this.list = recyclerView;
        this.llInput = linearLayout;
        this.pager = pageRefreshLayout;
    }

    @NonNull
    public static ChatDetailActBinding bind(@NonNull View view) {
        int i2 = R.id.btn_pic;
        ImageView imageView = (ImageView) view.findViewById(R.id.btn_pic);
        if (imageView != null) {
            i2 = R.id.btn_send;
            ImageView imageView2 = (ImageView) view.findViewById(R.id.btn_send);
            if (imageView2 != null) {
                i2 = R.id.ed_input;
                EditText editText = (EditText) view.findViewById(R.id.ed_input);
                if (editText != null) {
                    i2 = R.id.list;
                    RecyclerView recyclerView = (RecyclerView) view.findViewById(R.id.list);
                    if (recyclerView != null) {
                        i2 = R.id.ll_input;
                        LinearLayout linearLayout = (LinearLayout) view.findViewById(R.id.ll_input);
                        if (linearLayout != null) {
                            i2 = R.id.pager;
                            PageRefreshLayout pageRefreshLayout = (PageRefreshLayout) view.findViewById(R.id.pager);
                            if (pageRefreshLayout != null) {
                                return new ChatDetailActBinding((LinearLayoutCompat) view, imageView, imageView2, editText, recyclerView, linearLayout, pageRefreshLayout);
                            }
                        }
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static ChatDetailActBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static ChatDetailActBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.chat_detail_act, viewGroup, false);
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
