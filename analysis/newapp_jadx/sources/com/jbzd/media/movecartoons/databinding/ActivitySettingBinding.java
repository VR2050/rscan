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
public final class ActivitySettingBinding implements ViewBinding {

    @NonNull
    public final LinearLayoutCompat layoutAccountCreate;

    @NonNull
    public final LinearLayoutCompat layoutAvatarInfo;

    @NonNull
    public final LinearLayoutCompat layoutClearCache;

    @NonNull
    public final LinearLayoutCompat layoutFindAccount;

    @NonNull
    public final LinearLayoutCompat layoutUserNick;

    @NonNull
    public final LinearLayoutCompat layoutUserSex;

    @NonNull
    private final LinearLayoutCompat rootView;

    @NonNull
    public final TextView tvSizeCache;

    @NonNull
    public final TextView tvVersionName;

    private ActivitySettingBinding(@NonNull LinearLayoutCompat linearLayoutCompat, @NonNull LinearLayoutCompat linearLayoutCompat2, @NonNull LinearLayoutCompat linearLayoutCompat3, @NonNull LinearLayoutCompat linearLayoutCompat4, @NonNull LinearLayoutCompat linearLayoutCompat5, @NonNull LinearLayoutCompat linearLayoutCompat6, @NonNull LinearLayoutCompat linearLayoutCompat7, @NonNull TextView textView, @NonNull TextView textView2) {
        this.rootView = linearLayoutCompat;
        this.layoutAccountCreate = linearLayoutCompat2;
        this.layoutAvatarInfo = linearLayoutCompat3;
        this.layoutClearCache = linearLayoutCompat4;
        this.layoutFindAccount = linearLayoutCompat5;
        this.layoutUserNick = linearLayoutCompat6;
        this.layoutUserSex = linearLayoutCompat7;
        this.tvSizeCache = textView;
        this.tvVersionName = textView2;
    }

    @NonNull
    public static ActivitySettingBinding bind(@NonNull View view) {
        int i2 = R.id.layout_account_create;
        LinearLayoutCompat linearLayoutCompat = (LinearLayoutCompat) view.findViewById(R.id.layout_account_create);
        if (linearLayoutCompat != null) {
            i2 = R.id.layout_avatar_info;
            LinearLayoutCompat linearLayoutCompat2 = (LinearLayoutCompat) view.findViewById(R.id.layout_avatar_info);
            if (linearLayoutCompat2 != null) {
                i2 = R.id.layout_clear_cache;
                LinearLayoutCompat linearLayoutCompat3 = (LinearLayoutCompat) view.findViewById(R.id.layout_clear_cache);
                if (linearLayoutCompat3 != null) {
                    i2 = R.id.layout_find_account;
                    LinearLayoutCompat linearLayoutCompat4 = (LinearLayoutCompat) view.findViewById(R.id.layout_find_account);
                    if (linearLayoutCompat4 != null) {
                        i2 = R.id.layout_user_nick;
                        LinearLayoutCompat linearLayoutCompat5 = (LinearLayoutCompat) view.findViewById(R.id.layout_user_nick);
                        if (linearLayoutCompat5 != null) {
                            i2 = R.id.layout_user_sex;
                            LinearLayoutCompat linearLayoutCompat6 = (LinearLayoutCompat) view.findViewById(R.id.layout_user_sex);
                            if (linearLayoutCompat6 != null) {
                                i2 = R.id.tv_size_cache;
                                TextView textView = (TextView) view.findViewById(R.id.tv_size_cache);
                                if (textView != null) {
                                    i2 = R.id.tv_version_name;
                                    TextView textView2 = (TextView) view.findViewById(R.id.tv_version_name);
                                    if (textView2 != null) {
                                        return new ActivitySettingBinding((LinearLayoutCompat) view, linearLayoutCompat, linearLayoutCompat2, linearLayoutCompat3, linearLayoutCompat4, linearLayoutCompat5, linearLayoutCompat6, textView, textView2);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static ActivitySettingBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static ActivitySettingBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.activity_setting, viewGroup, false);
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
