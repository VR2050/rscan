package im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui;

import android.content.Context;
import android.text.TextUtils;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.LinearLayout;
import android.widget.TextView;
import im.uwrkaxlmjj.javaBean.fc.FcLocationInfoBean;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.ui.actionbar.ActionBar;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class FcLocationInfoActivity extends BaseFragment {
    private FcLocationInfoBean fcLocationInfoBean;
    private LinearLayout ll_location_address;
    private Context mContext;
    private TextView tv_location_address;
    private TextView tv_location_name;

    public FcLocationInfoActivity(FcLocationInfoBean fcLocationInfoBean) {
        this.fcLocationInfoBean = fcLocationInfoBean;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public View createView(Context context) {
        this.mContext = context;
        this.fragmentView = LayoutInflater.from(context).inflate(R.layout.activity_friends_cricle_location_info, (ViewGroup) null);
        this.fragmentView.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundGray));
        initActionBar();
        initView();
        initData();
        return this.fragmentView;
    }

    private void initData() {
        FcLocationInfoBean fcLocationInfoBean = this.fcLocationInfoBean;
        if (fcLocationInfoBean != null) {
            String locationName = fcLocationInfoBean.getLocationName();
            String locationAddress = this.fcLocationInfoBean.getLocationAddress();
            String locationCity = this.fcLocationInfoBean.getLocationCity();
            if (!TextUtils.isEmpty(locationName)) {
                if (TextUtils.equals(locationName, locationAddress)) {
                    this.tv_location_name.setText(locationName);
                    this.ll_location_address.setVisibility(8);
                    return;
                }
                if (!TextUtils.isEmpty(locationName)) {
                    if (!TextUtils.isEmpty(locationCity) && !TextUtils.equals(locationName, locationCity)) {
                        locationName = locationCity.replace("市", "") + "·" + locationName;
                    }
                    this.tv_location_name.setText(locationName);
                }
                if (TextUtils.isEmpty(locationAddress)) {
                    this.ll_location_address.setVisibility(8);
                } else {
                    this.tv_location_address.setText(locationAddress);
                }
            }
        }
    }

    private void initView() {
        this.tv_location_name = (TextView) this.fragmentView.findViewById(R.attr.tv_location_name);
        this.ll_location_address = (LinearLayout) this.fragmentView.findViewById(R.attr.ll_location_address);
        this.tv_location_address = (TextView) this.fragmentView.findViewById(R.attr.tv_location_address);
    }

    private void initActionBar() {
        this.actionBar.setTitle(LocaleController.getString("friendscircle_location_info_title", R.string.friendscircle_location_info_title));
        this.actionBar.setBackButtonImage(R.id.ic_back);
        this.actionBar.setAllowOverlayTitle(true);
        if (AndroidUtilities.isTablet()) {
            this.actionBar.setOccupyStatusBar(false);
        }
        this.actionBar.setActionBarMenuOnItemClick(new ActionBar.ActionBarMenuOnItemClick() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.FcLocationInfoActivity.1
            @Override // im.uwrkaxlmjj.ui.actionbar.ActionBar.ActionBarMenuOnItemClick
            public void onItemClick(int id) {
                if (id == -1) {
                    FcLocationInfoActivity.this.finishFragment();
                }
            }
        });
    }
}
