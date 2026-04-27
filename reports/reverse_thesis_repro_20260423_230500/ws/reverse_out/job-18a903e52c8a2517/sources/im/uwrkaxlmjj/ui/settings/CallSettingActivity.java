package im.uwrkaxlmjj.ui.settings;

import android.content.Context;
import android.graphics.PorterDuff;
import android.graphics.PorterDuffColorFilter;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.ui.actionbar.ActionBar;
import im.uwrkaxlmjj.ui.actionbar.ActionBarMenu;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.settings.DataAndStoreSettingActivity;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class CallSettingActivity extends BaseFragment {
    private static final int SAVE_BUTTON = 1;
    private ImageView mIvAlways;
    private ImageView mIvCurrent;
    private ImageView mIvMobile;
    private ImageView mIvNever;
    private DataAndStoreSettingActivity.CallSettingSelectedListener mListener;
    private int miSelected;

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public View createView(Context context) {
        this.actionBar.setBackButtonImage(R.id.ic_back);
        this.actionBar.setTitle(LocaleController.getString("VoipNotificationSettings", R.string.VoipNotificationSettings));
        if (AndroidUtilities.isTablet()) {
            this.actionBar.setOccupyStatusBar(false);
        }
        this.actionBar.setAllowOverlayTitle(true);
        ActionBarMenu menu = this.actionBar.createMenu();
        menu.addRightItemView(1, LocaleController.getString("Save", R.string.Save));
        this.fragmentView = LayoutInflater.from(context).inflate(R.layout.activity_setting_call, (ViewGroup) null, false);
        this.fragmentView.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundGray));
        initView(context);
        initListener();
        return this.fragmentView;
    }

    public CallSettingActivity(int iSelected, DataAndStoreSettingActivity.CallSettingSelectedListener listener) {
        this.mListener = null;
        this.miSelected = iSelected;
        this.mListener = listener;
    }

    private void initView(Context context) {
        this.mIvNever = (ImageView) this.fragmentView.findViewById(R.attr.iv_never);
        this.mIvMobile = (ImageView) this.fragmentView.findViewById(R.attr.iv_mobile);
        this.mIvAlways = (ImageView) this.fragmentView.findViewById(R.attr.iv_always);
        if (this.miSelected == 1) {
            this.miSelected = 0;
        }
        this.mIvNever.setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_featuredStickers_addedIcon), PorterDuff.Mode.SRC_IN));
        this.mIvMobile.setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_featuredStickers_addedIcon), PorterDuff.Mode.SRC_IN));
        this.mIvAlways.setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_featuredStickers_addedIcon), PorterDuff.Mode.SRC_IN));
        int i = this.miSelected;
        if (i == 0) {
            ImageView imageView = this.mIvNever;
            this.mIvCurrent = imageView;
            imageView.setImageDrawable(getParentActivity().getResources().getDrawable(R.id.ic_selected));
        } else if (i == 2) {
            ImageView imageView2 = this.mIvMobile;
            this.mIvCurrent = imageView2;
            imageView2.setImageDrawable(getParentActivity().getResources().getDrawable(R.id.ic_selected));
        } else if (i == 3) {
            ImageView imageView3 = this.mIvAlways;
            this.mIvCurrent = imageView3;
            imageView3.setImageDrawable(getParentActivity().getResources().getDrawable(R.id.ic_selected));
        }
        this.fragmentView.findViewById(R.attr.rl_never).setBackground(Theme.getRoundRectSelectorDrawable(AndroidUtilities.dp(5.0f), AndroidUtilities.dp(5.0f), 0, 0, Theme.getColor(Theme.key_windowBackgroundWhite)));
        this.fragmentView.findViewById(R.attr.rl_mobile).setBackground(Theme.getSelectorDrawable(true));
        this.fragmentView.findViewById(R.attr.rl_always).setBackground(Theme.getRoundRectSelectorDrawable(0, 0, AndroidUtilities.dp(5.0f), AndroidUtilities.dp(5.0f), Theme.getColor(Theme.key_windowBackgroundWhite)));
    }

    private void initListener() {
        this.actionBar.setActionBarMenuOnItemClick(new ActionBar.ActionBarMenuOnItemClick() { // from class: im.uwrkaxlmjj.ui.settings.CallSettingActivity.1
            @Override // im.uwrkaxlmjj.ui.actionbar.ActionBar.ActionBarMenuOnItemClick
            public void onItemClick(int id) {
                int iSeled;
                if (id == -1) {
                    CallSettingActivity.this.finishFragment();
                    return;
                }
                if (id == 1) {
                    if (CallSettingActivity.this.mListener != null) {
                        if (CallSettingActivity.this.mIvCurrent != CallSettingActivity.this.mIvNever) {
                            if (CallSettingActivity.this.mIvCurrent == CallSettingActivity.this.mIvMobile) {
                                iSeled = 2;
                            } else {
                                iSeled = 3;
                            }
                        } else {
                            iSeled = 0;
                        }
                        CallSettingActivity.this.mListener.onSeleted(iSeled);
                    }
                    CallSettingActivity.this.finishFragment();
                }
            }
        });
        this.fragmentView.findViewById(R.attr.rl_never).setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.settings.-$$Lambda$CallSettingActivity$sqHI2I7sUkOZycxWuEfA4zlmzEU
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$initListener$0$CallSettingActivity(view);
            }
        });
        this.fragmentView.findViewById(R.attr.rl_mobile).setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.settings.-$$Lambda$CallSettingActivity$yHkUGlZwPqA37Mx4CuURNst2z78
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$initListener$1$CallSettingActivity(view);
            }
        });
        this.fragmentView.findViewById(R.attr.rl_always).setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.settings.-$$Lambda$CallSettingActivity$6eDxv37wSZ1WX_HICP3pYcSMfmA
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$initListener$2$CallSettingActivity(view);
            }
        });
    }

    public /* synthetic */ void lambda$initListener$0$CallSettingActivity(View view) {
        ImageView imageView = this.mIvCurrent;
        ImageView imageView2 = this.mIvNever;
        if (imageView != imageView2) {
            imageView2.setImageDrawable(getParentActivity().getResources().getDrawable(R.id.ic_selected));
            this.mIvCurrent.setImageDrawable(null);
            this.mIvCurrent = this.mIvNever;
        }
    }

    public /* synthetic */ void lambda$initListener$1$CallSettingActivity(View view) {
        ImageView imageView = this.mIvCurrent;
        ImageView imageView2 = this.mIvMobile;
        if (imageView != imageView2) {
            imageView2.setImageDrawable(getParentActivity().getResources().getDrawable(R.id.ic_selected));
            this.mIvCurrent.setImageDrawable(null);
            this.mIvCurrent = this.mIvMobile;
        }
    }

    public /* synthetic */ void lambda$initListener$2$CallSettingActivity(View view) {
        ImageView imageView = this.mIvCurrent;
        ImageView imageView2 = this.mIvAlways;
        if (imageView != imageView2) {
            imageView2.setImageDrawable(getParentActivity().getResources().getDrawable(R.id.ic_selected));
            this.mIvCurrent.setImageDrawable(null);
            this.mIvCurrent = this.mIvAlways;
        }
    }
}
