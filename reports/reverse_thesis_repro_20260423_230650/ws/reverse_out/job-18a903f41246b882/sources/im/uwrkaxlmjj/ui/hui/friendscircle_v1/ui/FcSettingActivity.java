package im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui;

import android.view.View;
import com.bjz.comm.net.bean.BResponse;
import com.bjz.comm.net.bean.FCEntitysRequest;
import com.bjz.comm.net.bean.FcIgnoreUserBean;
import com.bjz.comm.net.bean.RespFcIgnoreBean;
import com.bjz.comm.net.factory.ApiFactory;
import com.bjz.comm.net.utils.RxHelper;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.NotificationCenter;
import im.uwrkaxlmjj.messenger.UserConfig;
import im.uwrkaxlmjj.ui.actionbar.ActionBar;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.components.ColorTextView;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.base.CommFcListActivity;
import im.uwrkaxlmjj.ui.hviews.MrySwitch;
import io.reactivex.Observable;
import io.reactivex.functions.Consumer;
import java.util.ArrayList;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class FcSettingActivity extends CommFcListActivity {
    private static final String TAG = FcSettingActivity.class.getSimpleName();
    private MrySwitch mSwitchLookMyFc;
    private MrySwitch mSwitchLookOtherFc;
    private int sex;
    private long userId;

    public FcSettingActivity(long userId, int sex) {
        this.userId = userId;
        this.sex = sex;
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.base.BaseFcActivity
    protected int getLayoutRes() {
        return R.layout.activity_friends_cricle_setting;
    }

    protected void initActionBar() {
        this.actionBar.setTitle(LocaleController.getString("friends_circle_setting", R.string.friends_circle_setting));
        this.actionBar.setBackButtonImage(R.id.ic_back);
        this.actionBar.setActionBarMenuOnItemClick(new ActionBar.ActionBarMenuOnItemClick() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.FcSettingActivity.1
            @Override // im.uwrkaxlmjj.ui.actionbar.ActionBar.ActionBarMenuOnItemClick
            public void onItemClick(int id) {
                if (id == -1) {
                    FcSettingActivity.this.finishFragment();
                }
            }
        });
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.base.BaseFcActivity
    protected void initView() {
        initActionBar();
        this.fragmentView.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundGray));
        ColorTextView txt_report1 = (ColorTextView) this.fragmentView.findViewById(R.attr.txt_report1);
        ColorTextView txt_report2 = (ColorTextView) this.fragmentView.findViewById(R.attr.txt_report2);
        int i = this.sex;
        if (i != 0) {
            if (i == 1) {
                txt_report1.setText(LocaleController.getString(R.string.friendscircle_dont_let_him_look));
                txt_report2.setText(LocaleController.getString(R.string.friendscircle_dont_look_him));
            } else if (i == 2) {
                txt_report1.setText(LocaleController.getString(R.string.friendscircle_dont_let_her_look));
                txt_report2.setText(LocaleController.getString(R.string.friendscircle_dont_look_her));
            }
        }
        this.mSwitchLookMyFc = (MrySwitch) this.fragmentView.findViewById(R.attr.switch_look_me);
        this.mSwitchLookOtherFc = (MrySwitch) this.fragmentView.findViewById(R.attr.switch_look_other);
        this.mSwitchLookMyFc.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.FcSettingActivity.2
            @Override // android.view.View.OnClickListener
            public void onClick(View v) {
                if (FcSettingActivity.this.mSwitchLookMyFc.isChecked()) {
                    ArrayList<FcIgnoreUserBean> ignores = new ArrayList<>();
                    ignores.add(new FcIgnoreUserBean(FcSettingActivity.this.userId, 1));
                    FcSettingActivity.this.doDeleteIgnoreUser(ignores);
                } else {
                    ArrayList<FcIgnoreUserBean> ignores2 = new ArrayList<>();
                    ignores2.add(new FcIgnoreUserBean(FcSettingActivity.this.userId, 1));
                    FcSettingActivity.this.doAddIgnoreUser(ignores2);
                }
            }
        });
        this.mSwitchLookOtherFc.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.FcSettingActivity.3
            @Override // android.view.View.OnClickListener
            public void onClick(View v) {
                if (FcSettingActivity.this.mSwitchLookOtherFc.isChecked()) {
                    ArrayList<FcIgnoreUserBean> ignores = new ArrayList<>();
                    ignores.add(new FcIgnoreUserBean(FcSettingActivity.this.userId, 2));
                    FcSettingActivity.this.doDeleteIgnoreUser(ignores);
                } else {
                    ArrayList<FcIgnoreUserBean> ignores2 = new ArrayList<>();
                    ignores2.add(new FcIgnoreUserBean(FcSettingActivity.this.userId, 2));
                    FcSettingActivity.this.doAddIgnoreUser(ignores2);
                }
            }
        });
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.base.CommFcListActivity, com.bjz.comm.net.mvp.contract.BaseFcContract.IFcCommItemView
    public void doAddIgnoreUserSucc(ArrayList<FcIgnoreUserBean> ignores, String msg) {
        doSetIgnoreUserAfterViewChange(true, ignores);
        NotificationCenter.getInstance(UserConfig.selectedAccount).postNotificationName(NotificationCenter.fcIgnoreUser, TAG, ignores);
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.base.CommFcListActivity, com.bjz.comm.net.mvp.contract.BaseFcContract.IFcCommItemView
    public void doAddIgnoreUserFailed(String msg) {
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.base.CommFcListActivity, com.bjz.comm.net.mvp.contract.BaseFcContract.IFcCommItemView
    public void doDeleteIgnoreUserSucc(ArrayList<FcIgnoreUserBean> ignores, String msg) {
        doSetIgnoreUserAfterViewChange(false, ignores);
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.base.CommFcListActivity, com.bjz.comm.net.mvp.contract.BaseFcContract.IFcCommItemView
    public void doDeleteIgnoreUserFiled(String msg) {
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.base.CommFcListActivity
    protected void doSetIgnoreUserAfterViewChange(boolean isIgnore, ArrayList<FcIgnoreUserBean> ignores) {
        FcIgnoreUserBean ignoreUserBean;
        if (ignores != null && ignores.size() > 0 && (ignoreUserBean = ignores.get(0)) != null) {
            int look = ignoreUserBean.getLook();
            if (look == 1) {
                this.mSwitchLookMyFc.setChecked(isIgnore, true);
            } else if (look == 2) {
                this.mSwitchLookOtherFc.setChecked(isIgnore, true);
            }
        }
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.base.BaseFcActivity
    protected void initData() {
        getFcIgnoreSetting();
    }

    private void getFcIgnoreSetting() {
        Observable<BResponse<RespFcIgnoreBean>> observable = ApiFactory.getInstance().getApiMomentForum().getUserIgnoreSetting(this.userId);
        RxHelper.getInstance().sendRequest(TAG, observable, new Consumer() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$FcSettingActivity$YGklQ89FkVSUaN1PiLSqQvkGL1k
            @Override // io.reactivex.functions.Consumer
            public final void accept(Object obj) throws Exception {
                this.f$0.lambda$getFcIgnoreSetting$0$FcSettingActivity((BResponse) obj);
            }
        }, new Consumer() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$FcSettingActivity$4Bv5q4MLAnnQXtdTvKM-IHfs2nM
            @Override // io.reactivex.functions.Consumer
            public final void accept(Object obj) throws Exception {
                FcSettingActivity.lambda$getFcIgnoreSetting$1((Throwable) obj);
            }
        });
    }

    /* JADX WARN: Multi-variable type inference failed */
    public /* synthetic */ void lambda$getFcIgnoreSetting$0$FcSettingActivity(BResponse response) throws Exception {
        RespFcIgnoreBean data;
        if (response.isState() && (data = (RespFcIgnoreBean) response.Data) != null) {
            this.mSwitchLookMyFc.setChecked(data.isLookMe(), true);
            this.mSwitchLookOtherFc.setChecked(data.isLookOther(), true);
        }
    }

    static /* synthetic */ void lambda$getFcIgnoreSetting$1(Throwable throwable) throws Exception {
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.FcDoReplyDialog.OnFcDoReplyListener
    public void onInputReplyContent(String content, ArrayList<FCEntitysRequest> atUserBeanList) {
    }
}
