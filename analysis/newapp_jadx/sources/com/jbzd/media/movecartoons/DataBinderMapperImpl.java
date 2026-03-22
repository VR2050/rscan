package com.jbzd.media.movecartoons;

import android.util.SparseArray;
import android.util.SparseIntArray;
import android.view.View;
import androidx.databinding.DataBinderMapper;
import androidx.databinding.DataBindingComponent;
import androidx.databinding.ViewDataBinding;
import com.jbzd.media.movecartoons.databinding.ActExchangeBindingImpl;
import com.jbzd.media.movecartoons.databinding.ActFindBindingImpl;
import com.jbzd.media.movecartoons.databinding.ActLoginInputBindingImpl;
import com.jbzd.media.movecartoons.databinding.ActRegisterInputBindingImpl;
import com.jbzd.media.movecartoons.databinding.ActShareBindBindingImpl;
import com.jbzd.media.movecartoons.databinding.ActivityPersonalInfoBindingImpl;
import com.jbzd.media.movecartoons.databinding.ItemAppBannerBindingImpl;
import com.jbzd.media.movecartoons.databinding.ItemAppVerticalBindingImpl;
import com.jbzd.media.movecartoons.databinding.ItemBottomMineBindingImpl;
import com.jbzd.media.movecartoons.databinding.ItemComicLayoutBindingImpl;
import com.jbzd.media.movecartoons.databinding.ItemExchangeBindingImpl;
import com.jbzd.media.movecartoons.databinding.ItemFollowBindingImpl;
import com.jbzd.media.movecartoons.databinding.ItemIncomeLogBindingImpl;
import com.jbzd.media.movecartoons.databinding.ItemMemberRightsBindingImpl;
import com.jbzd.media.movecartoons.databinding.ItemMineGridBindingImpl;
import com.jbzd.media.movecartoons.databinding.ItemMineHandlerBindingImpl;
import com.jbzd.media.movecartoons.databinding.ItemNovelLayoutBindingImpl;
import com.jbzd.media.movecartoons.databinding.ItemPayTypeVerticalBindingImpl;
import com.jbzd.media.movecartoons.databinding.ItemPostLayoutBindingImpl;
import com.jbzd.media.movecartoons.databinding.ItemRechargeCoinBindingImpl;
import com.jbzd.media.movecartoons.databinding.ItemShareBindingImpl;
import com.jbzd.media.movecartoons.databinding.ItemUnlockAccountBindingImpl;
import com.jbzd.media.movecartoons.databinding.ItemUnlockVideoBindingImpl;
import com.jbzd.media.movecartoons.databinding.ItemVideoLayoutBindingImpl;
import com.jbzd.media.movecartoons.databinding.LayoutItemPostUserBindingImpl;
import com.qnmd.adnnm.da0yzo.R;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import p005b.p131d.p132a.p133a.C1499a;

/* loaded from: classes2.dex */
public class DataBinderMapperImpl extends DataBinderMapper {

    /* renamed from: a */
    public static final SparseIntArray f9888a;

    /* renamed from: com.jbzd.media.movecartoons.DataBinderMapperImpl$a */
    public static class C3616a {

        /* renamed from: a */
        public static final SparseArray<String> f9889a;

        static {
            SparseArray<String> sparseArray = new SparseArray<>(6);
            f9889a = sparseArray;
            sparseArray.put(0, "_all");
            sparseArray.put(1, "item");
            sparseArray.put(2, "time");
            sparseArray.put(3, "userBean");
            sparseArray.put(4, "userInfo");
            sparseArray.put(5, "viewModel");
        }
    }

    /* renamed from: com.jbzd.media.movecartoons.DataBinderMapperImpl$b */
    public static class C3617b {

        /* renamed from: a */
        public static final HashMap<String, Integer> f9890a;

        static {
            HashMap<String, Integer> hashMap = new HashMap<>(25);
            f9890a = hashMap;
            hashMap.put("layout/act_exchange_0", Integer.valueOf(R.layout.act_exchange));
            hashMap.put("layout/act_find_0", Integer.valueOf(R.layout.act_find));
            hashMap.put("layout/act_login_input_0", Integer.valueOf(R.layout.act_login_input));
            hashMap.put("layout/act_register_input_0", Integer.valueOf(R.layout.act_register_input));
            hashMap.put("layout/act_share_bind_0", Integer.valueOf(R.layout.act_share_bind));
            hashMap.put("layout/activity_personal_info_0", Integer.valueOf(R.layout.activity_personal_info));
            hashMap.put("layout/item_app_banner_0", Integer.valueOf(R.layout.item_app_banner));
            hashMap.put("layout/item_app_vertical_0", Integer.valueOf(R.layout.item_app_vertical));
            hashMap.put("layout/item_bottom_mine_0", Integer.valueOf(R.layout.item_bottom_mine));
            hashMap.put("layout/item_comic_layout_0", Integer.valueOf(R.layout.item_comic_layout));
            hashMap.put("layout/item_exchange_0", Integer.valueOf(R.layout.item_exchange));
            hashMap.put("layout/item_follow_0", Integer.valueOf(R.layout.item_follow));
            hashMap.put("layout/item_income_log_0", Integer.valueOf(R.layout.item_income_log));
            hashMap.put("layout/item_member_rights_0", Integer.valueOf(R.layout.item_member_rights));
            hashMap.put("layout/item_mine_grid_0", Integer.valueOf(R.layout.item_mine_grid));
            hashMap.put("layout/item_mine_handler_0", Integer.valueOf(R.layout.item_mine_handler));
            hashMap.put("layout/item_novel_layout_0", Integer.valueOf(R.layout.item_novel_layout));
            hashMap.put("layout/item_pay_type_vertical_0", Integer.valueOf(R.layout.item_pay_type_vertical));
            hashMap.put("layout/item_post_layout_0", Integer.valueOf(R.layout.item_post_layout));
            hashMap.put("layout/item_recharge_coin_0", Integer.valueOf(R.layout.item_recharge_coin));
            hashMap.put("layout/item_share_0", Integer.valueOf(R.layout.item_share));
            hashMap.put("layout/item_unlock_account_0", Integer.valueOf(R.layout.item_unlock_account));
            hashMap.put("layout/item_unlock_video_0", Integer.valueOf(R.layout.item_unlock_video));
            hashMap.put("layout/item_video_layout_0", Integer.valueOf(R.layout.item_video_layout));
            hashMap.put("layout/layout_item_post_user_0", Integer.valueOf(R.layout.layout_item_post_user));
        }
    }

    static {
        SparseIntArray sparseIntArray = new SparseIntArray(25);
        f9888a = sparseIntArray;
        sparseIntArray.put(R.layout.act_exchange, 1);
        sparseIntArray.put(R.layout.act_find, 2);
        sparseIntArray.put(R.layout.act_login_input, 3);
        sparseIntArray.put(R.layout.act_register_input, 4);
        sparseIntArray.put(R.layout.act_share_bind, 5);
        sparseIntArray.put(R.layout.activity_personal_info, 6);
        sparseIntArray.put(R.layout.item_app_banner, 7);
        sparseIntArray.put(R.layout.item_app_vertical, 8);
        sparseIntArray.put(R.layout.item_bottom_mine, 9);
        sparseIntArray.put(R.layout.item_comic_layout, 10);
        sparseIntArray.put(R.layout.item_exchange, 11);
        sparseIntArray.put(R.layout.item_follow, 12);
        sparseIntArray.put(R.layout.item_income_log, 13);
        sparseIntArray.put(R.layout.item_member_rights, 14);
        sparseIntArray.put(R.layout.item_mine_grid, 15);
        sparseIntArray.put(R.layout.item_mine_handler, 16);
        sparseIntArray.put(R.layout.item_novel_layout, 17);
        sparseIntArray.put(R.layout.item_pay_type_vertical, 18);
        sparseIntArray.put(R.layout.item_post_layout, 19);
        sparseIntArray.put(R.layout.item_recharge_coin, 20);
        sparseIntArray.put(R.layout.item_share, 21);
        sparseIntArray.put(R.layout.item_unlock_account, 22);
        sparseIntArray.put(R.layout.item_unlock_video, 23);
        sparseIntArray.put(R.layout.item_video_layout, 24);
        sparseIntArray.put(R.layout.layout_item_post_user, 25);
    }

    @Override // androidx.databinding.DataBinderMapper
    public List<DataBinderMapper> collectDependencies() {
        ArrayList arrayList = new ArrayList(4);
        arrayList.add(new androidx.databinding.library.baseAdapters.DataBinderMapperImpl());
        arrayList.add(new com.chad.library.DataBinderMapperImpl());
        arrayList.add(new com.drake.brv.DataBinderMapperImpl());
        arrayList.add(new com.qunidayede.supportlibrary.DataBinderMapperImpl());
        return arrayList;
    }

    @Override // androidx.databinding.DataBinderMapper
    public String convertBrIdToString(int i2) {
        return C3616a.f9889a.get(i2);
    }

    @Override // androidx.databinding.DataBinderMapper
    public ViewDataBinding getDataBinder(DataBindingComponent dataBindingComponent, View view, int i2) {
        int i3 = f9888a.get(i2);
        if (i3 <= 0) {
            return null;
        }
        Object tag = view.getTag();
        if (tag == null) {
            throw new RuntimeException("view must have a tag");
        }
        switch (i3) {
            case 1:
                if ("layout/act_exchange_0".equals(tag)) {
                    return new ActExchangeBindingImpl(dataBindingComponent, view);
                }
                throw new IllegalArgumentException(C1499a.m636v("The tag for act_exchange is invalid. Received: ", tag));
            case 2:
                if ("layout/act_find_0".equals(tag)) {
                    return new ActFindBindingImpl(dataBindingComponent, view);
                }
                throw new IllegalArgumentException(C1499a.m636v("The tag for act_find is invalid. Received: ", tag));
            case 3:
                if ("layout/act_login_input_0".equals(tag)) {
                    return new ActLoginInputBindingImpl(dataBindingComponent, view);
                }
                throw new IllegalArgumentException(C1499a.m636v("The tag for act_login_input is invalid. Received: ", tag));
            case 4:
                if ("layout/act_register_input_0".equals(tag)) {
                    return new ActRegisterInputBindingImpl(dataBindingComponent, view);
                }
                throw new IllegalArgumentException(C1499a.m636v("The tag for act_register_input is invalid. Received: ", tag));
            case 5:
                if ("layout/act_share_bind_0".equals(tag)) {
                    return new ActShareBindBindingImpl(dataBindingComponent, view);
                }
                throw new IllegalArgumentException(C1499a.m636v("The tag for act_share_bind is invalid. Received: ", tag));
            case 6:
                if ("layout/activity_personal_info_0".equals(tag)) {
                    return new ActivityPersonalInfoBindingImpl(dataBindingComponent, view);
                }
                throw new IllegalArgumentException(C1499a.m636v("The tag for activity_personal_info is invalid. Received: ", tag));
            case 7:
                if ("layout/item_app_banner_0".equals(tag)) {
                    return new ItemAppBannerBindingImpl(dataBindingComponent, view);
                }
                throw new IllegalArgumentException(C1499a.m636v("The tag for item_app_banner is invalid. Received: ", tag));
            case 8:
                if ("layout/item_app_vertical_0".equals(tag)) {
                    return new ItemAppVerticalBindingImpl(dataBindingComponent, view);
                }
                throw new IllegalArgumentException(C1499a.m636v("The tag for item_app_vertical is invalid. Received: ", tag));
            case 9:
                if ("layout/item_bottom_mine_0".equals(tag)) {
                    return new ItemBottomMineBindingImpl(dataBindingComponent, view);
                }
                throw new IllegalArgumentException(C1499a.m636v("The tag for item_bottom_mine is invalid. Received: ", tag));
            case 10:
                if ("layout/item_comic_layout_0".equals(tag)) {
                    return new ItemComicLayoutBindingImpl(dataBindingComponent, view);
                }
                throw new IllegalArgumentException(C1499a.m636v("The tag for item_comic_layout is invalid. Received: ", tag));
            case 11:
                if ("layout/item_exchange_0".equals(tag)) {
                    return new ItemExchangeBindingImpl(dataBindingComponent, view);
                }
                throw new IllegalArgumentException(C1499a.m636v("The tag for item_exchange is invalid. Received: ", tag));
            case 12:
                if ("layout/item_follow_0".equals(tag)) {
                    return new ItemFollowBindingImpl(dataBindingComponent, view);
                }
                throw new IllegalArgumentException(C1499a.m636v("The tag for item_follow is invalid. Received: ", tag));
            case 13:
                if ("layout/item_income_log_0".equals(tag)) {
                    return new ItemIncomeLogBindingImpl(dataBindingComponent, view);
                }
                throw new IllegalArgumentException(C1499a.m636v("The tag for item_income_log is invalid. Received: ", tag));
            case 14:
                if ("layout/item_member_rights_0".equals(tag)) {
                    return new ItemMemberRightsBindingImpl(dataBindingComponent, view);
                }
                throw new IllegalArgumentException(C1499a.m636v("The tag for item_member_rights is invalid. Received: ", tag));
            case 15:
                if ("layout/item_mine_grid_0".equals(tag)) {
                    return new ItemMineGridBindingImpl(dataBindingComponent, view);
                }
                throw new IllegalArgumentException(C1499a.m636v("The tag for item_mine_grid is invalid. Received: ", tag));
            case 16:
                if ("layout/item_mine_handler_0".equals(tag)) {
                    return new ItemMineHandlerBindingImpl(dataBindingComponent, view);
                }
                throw new IllegalArgumentException(C1499a.m636v("The tag for item_mine_handler is invalid. Received: ", tag));
            case 17:
                if ("layout/item_novel_layout_0".equals(tag)) {
                    return new ItemNovelLayoutBindingImpl(dataBindingComponent, view);
                }
                throw new IllegalArgumentException(C1499a.m636v("The tag for item_novel_layout is invalid. Received: ", tag));
            case 18:
                if ("layout/item_pay_type_vertical_0".equals(tag)) {
                    return new ItemPayTypeVerticalBindingImpl(dataBindingComponent, view);
                }
                throw new IllegalArgumentException(C1499a.m636v("The tag for item_pay_type_vertical is invalid. Received: ", tag));
            case 19:
                if ("layout/item_post_layout_0".equals(tag)) {
                    return new ItemPostLayoutBindingImpl(dataBindingComponent, view);
                }
                throw new IllegalArgumentException(C1499a.m636v("The tag for item_post_layout is invalid. Received: ", tag));
            case 20:
                if ("layout/item_recharge_coin_0".equals(tag)) {
                    return new ItemRechargeCoinBindingImpl(dataBindingComponent, view);
                }
                throw new IllegalArgumentException(C1499a.m636v("The tag for item_recharge_coin is invalid. Received: ", tag));
            case 21:
                if ("layout/item_share_0".equals(tag)) {
                    return new ItemShareBindingImpl(dataBindingComponent, view);
                }
                throw new IllegalArgumentException(C1499a.m636v("The tag for item_share is invalid. Received: ", tag));
            case 22:
                if ("layout/item_unlock_account_0".equals(tag)) {
                    return new ItemUnlockAccountBindingImpl(dataBindingComponent, view);
                }
                throw new IllegalArgumentException(C1499a.m636v("The tag for item_unlock_account is invalid. Received: ", tag));
            case 23:
                if ("layout/item_unlock_video_0".equals(tag)) {
                    return new ItemUnlockVideoBindingImpl(dataBindingComponent, view);
                }
                throw new IllegalArgumentException(C1499a.m636v("The tag for item_unlock_video is invalid. Received: ", tag));
            case 24:
                if ("layout/item_video_layout_0".equals(tag)) {
                    return new ItemVideoLayoutBindingImpl(dataBindingComponent, view);
                }
                throw new IllegalArgumentException(C1499a.m636v("The tag for item_video_layout is invalid. Received: ", tag));
            case 25:
                if ("layout/layout_item_post_user_0".equals(tag)) {
                    return new LayoutItemPostUserBindingImpl(dataBindingComponent, view);
                }
                throw new IllegalArgumentException(C1499a.m636v("The tag for layout_item_post_user is invalid. Received: ", tag));
            default:
                return null;
        }
    }

    @Override // androidx.databinding.DataBinderMapper
    public int getLayoutId(String str) {
        Integer num;
        if (str == null || (num = C3617b.f9890a.get(str)) == null) {
            return 0;
        }
        return num.intValue();
    }

    @Override // androidx.databinding.DataBinderMapper
    public ViewDataBinding getDataBinder(DataBindingComponent dataBindingComponent, View[] viewArr, int i2) {
        if (viewArr == null || viewArr.length == 0 || f9888a.get(i2) <= 0 || viewArr[0].getTag() != null) {
            return null;
        }
        throw new RuntimeException("view must have a tag");
    }
}
