package im.uwrkaxlmjj.ui.hui.cdnvip;

import android.app.Dialog;
import android.content.Context;
import android.content.DialogInterface;
import android.graphics.PorterDuff;
import android.graphics.PorterDuffColorFilter;
import android.text.TextPaint;
import android.text.TextUtils;
import android.text.style.ClickableSpan;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.AdapterView;
import android.widget.FrameLayout;
import android.widget.GridView;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ListAdapter;
import android.widget.RelativeLayout;
import android.widget.TextView;
import androidx.recyclerview.widget.GridLayoutManager;
import butterknife.BindView;
import butterknife.OnClick;
import com.blankj.utilcode.util.GsonUtils;
import com.blankj.utilcode.util.ScreenUtils;
import com.blankj.utilcode.util.SpanUtils;
import com.litesuits.orm.db.assit.SQLBuilder;
import im.uwrkaxlmjj.javaBean.cdnVip.CdnVipInfoBean;
import im.uwrkaxlmjj.javaBean.cdnVip.CdnVipUnitPriceBean;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.BuildVars;
import im.uwrkaxlmjj.messenger.ImageLocation;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.NotificationCenter;
import im.uwrkaxlmjj.messenger.UserObject;
import im.uwrkaxlmjj.messenger.utils.DataTools;
import im.uwrkaxlmjj.tgnet.ParamsUtil;
import im.uwrkaxlmjj.tgnet.RequestDelegate;
import im.uwrkaxlmjj.tgnet.TLApiModel;
import im.uwrkaxlmjj.tgnet.TLJsonResolve;
import im.uwrkaxlmjj.tgnet.TLObject;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.tgnet.TLRPCCdn;
import im.uwrkaxlmjj.tgnet.TLRPCFriendsHub;
import im.uwrkaxlmjj.tgnet.TLRPCWallet;
import im.uwrkaxlmjj.ui.actionbar.ActionBar;
import im.uwrkaxlmjj.ui.actionbar.ActionBarMenu;
import im.uwrkaxlmjj.ui.actionbar.ActionBarMenuItem;
import im.uwrkaxlmjj.ui.actionbar.AlertDialog;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.actionbar.BottomSheet;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.components.AvatarDrawable;
import im.uwrkaxlmjj.ui.components.BackupImageView;
import im.uwrkaxlmjj.ui.components.LayoutHelper;
import im.uwrkaxlmjj.ui.components.RecyclerListView;
import im.uwrkaxlmjj.ui.hui.adapter.KeyboardAdapter;
import im.uwrkaxlmjj.ui.hui.adapter.pageAdapter.PageHolder;
import im.uwrkaxlmjj.ui.hui.adapter.pageAdapter.PageSelectionAdapter;
import im.uwrkaxlmjj.ui.hui.cdnvip.CdnVipDetailsActivity;
import im.uwrkaxlmjj.ui.hui.mine.AboutAppActivity;
import im.uwrkaxlmjj.ui.hui.wallet_public.bean.WalletAccountInfo;
import im.uwrkaxlmjj.ui.hui.wallet_public.bean.WalletConfigBean;
import im.uwrkaxlmjj.ui.hui.wallet_public.utils.WalletDialogUtil;
import im.uwrkaxlmjj.ui.hui.wallet_public.utils.WalletErrorUtil;
import im.uwrkaxlmjj.ui.hviews.MryLinearLayout;
import im.uwrkaxlmjj.ui.hviews.MryTextView;
import im.uwrkaxlmjj.ui.utils.AesUtils;
import im.uwrkaxlmjj.ui.utils.number.NumberUtil;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import mpEIGo.juqQQs.esbSDO.R;
import org.json.JSONObject;

/* JADX INFO: loaded from: classes5.dex */
public class CdnVipCenterActivity extends BaseFragment implements CdnVipDetailsActivity.Delegate {
    private WalletAccountInfo accountInfo;

    @BindView(R.attr.actionBarContainer)
    FrameLayout actionBarContainer;
    private PageSelectionAdapter<Integer, PageHolder> adapter;

    @BindView(R.attr.btn)
    MryTextView btn;

    @BindView(R.attr.card)
    View card;
    private String cdnPrice;
    private CdnVipInfoBean cdnVipInfoBean;

    @BindView(R.attr.ivAvatar)
    BackupImageView ivAvatar;

    @BindView(R.attr.ivBgBottom)
    ImageView ivBgBottom;

    @BindView(R.attr.ivBgTop)
    ImageView ivBgTop;

    @BindView(R.attr.llBottom)
    View llBottom;
    private LinearLayout llPayPassword;
    private List<Integer> mNumbers = new ArrayList(Arrays.asList(1, 2, 3, 4, 5, 6, 7, 8, 9, -10, 0, -11));
    private TextView[] mTvPasswords;
    private int notEmptyTvCount;

    @BindView(R.attr.rv)
    RecyclerListView rv;

    @BindView(R.attr.tvBottomTips)
    TextView tvBottomTips;
    private TextView tvForgotPassword;

    @BindView(R.attr.tvStatusOrTime)
    MryTextView tvStatusOrTime;

    @BindView(R.attr.tvTeQuan)
    MryTextView tvTeQuan;

    @BindView(R.attr.tvTime)
    MryTextView tvTime;

    @BindView(R.attr.tvTips)
    MryTextView tvTips;

    @BindView(R.attr.tvUnitPrice)
    MryTextView tvUnitPrice;

    @BindView(R.attr.tvUserName)
    MryTextView tvUserName;

    @BindView(R.attr.tvVipTop)
    MryTextView tvVipTop;
    private TLRPC.User user;

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public boolean onFragmentCreate() {
        TLRPC.User user = getMessagesController().getUser(Integer.valueOf(getUserConfig().getClientUserId()));
        this.user = user;
        return user != null;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public View createView(Context context) {
        this.fragmentView = LayoutInflater.from(context).inflate(R.layout.activity_cdn_vip_center, (ViewGroup) null, false);
        useButterKnife();
        this.fragmentView.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundGray));
        initActionBar(this.fragmentView.findViewById(R.attr.actionBarContainer));
        initView(context);
        initRv(context);
        this.fragmentView.postDelayed(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.cdnvip.-$$Lambda$CdnVipCenterActivity$IexHTYC8NHG4H1wdWtWhIueElT8
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.getUserCdnVipInfo();
            }
        }, 300L);
        return this.fragmentView;
    }

    private void initActionBar(View container) {
        this.actionBar.setAddToContainer(false);
        this.actionBar.setBackButtonImage(R.id.ic_back);
        this.actionBar.setBackgroundColor(0);
        this.actionBar.setTitle(LocaleController.getString(R.string.VipCenter));
        this.actionBar.setActionBarMenuOnItemClick(new ActionBar.ActionBarMenuOnItemClick() { // from class: im.uwrkaxlmjj.ui.hui.cdnvip.CdnVipCenterActivity.1
            @Override // im.uwrkaxlmjj.ui.actionbar.ActionBar.ActionBarMenuOnItemClick
            public void onItemClick(int id) {
                if (id == -1) {
                    CdnVipCenterActivity.this.finishFragment();
                } else {
                    CdnVipCenterActivity cdnVipCenterActivity = CdnVipCenterActivity.this;
                    cdnVipCenterActivity.presentFragment(new CdnVipDetailsActivity(cdnVipCenterActivity.cdnVipInfoBean).setDelegate(CdnVipCenterActivity.this));
                }
            }
        });
        ActionBarMenu menuView = this.actionBar.createMenu();
        ActionBarMenuItem item = menuView.addItem(1, LocaleController.getString(R.string.MemberDetails));
        ((TextView) item.getContentView()).setTypeface(null);
        ((TextView) item.getContentView()).setTextSize(14.0f);
        this.actionBarContainer.addView(this.actionBar, LayoutHelper.createFrame(-1, -2, 80));
    }

    private void initView(Context context) {
        this.ivAvatar.setRoundRadius(AndroidUtilities.dp(8.0f));
        this.ivAvatar.setImage(ImageLocation.getForUser(this.user, false), "65_65", new AvatarDrawable(this.user), this.user);
        this.tvUserName.setText(UserObject.getName(this.user));
        this.tvVipTop.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteGrayText3));
        this.llBottom.bringToFront();
        if (Theme.getCurrentTheme() != null && Theme.getCurrentTheme().isDark()) {
            this.ivBgTop.setColorFilter(new PorterDuffColorFilter(AndroidUtilities.alphaColor(0.1f, Theme.getColor(Theme.key_windowBackgroundGray)), PorterDuff.Mode.MULTIPLY));
            this.ivBgBottom.setColorFilter(new PorterDuffColorFilter(AndroidUtilities.alphaColor(0.1f, Theme.getColor(Theme.key_windowBackgroundGray)), PorterDuff.Mode.MULTIPLY));
        }
        if (ScreenUtils.getAppScreenHeight() >= 2340) {
            int size = ScreenUtils.getScreenHeight() - AndroidUtilities.dp(160.0f);
            this.llBottom.setLayoutParams(new RelativeLayout.LayoutParams(-1, size));
            LinearLayout.LayoutParams lp = (LinearLayout.LayoutParams) this.tvBottomTips.getLayoutParams();
            lp.height = 0;
            lp.weight = 1.0f;
            this.tvBottomTips.setLayoutParams(lp);
        }
        this.card.setBackground(Theme.createRoundRectDrawable(AndroidUtilities.dp(8.0f), Theme.getColor(Theme.key_windowBackgroundWhite)));
        this.tvTips.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteGrayText3));
        this.tvBottomTips.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteGrayText3));
        SpanUtils.with(this.tvTime).append("30").setFontSize(45, true).append(LocaleController.getString(R.string.TimeUnitOfDay)).setFontSize(20, true).setVerticalAlign(0).create();
        SpanUtils.with(this.tvBottomTips).append(LocaleController.getString(R.string.CdbVipBottomTips1)).append(LocaleController.getString(R.string.AppVIPMembershipAgreement)).setClickSpan(new ClickableSpan() { // from class: im.uwrkaxlmjj.ui.hui.cdnvip.CdnVipCenterActivity.3
            @Override // android.text.style.ClickableSpan
            public void onClick(View widget) {
            }

            @Override // android.text.style.ClickableSpan, android.text.style.CharacterStyle
            public void updateDrawState(TextPaint ds) {
                ds.setColor(Theme.getColor(Theme.key_windowBackgroundWhiteGrayText3));
                ds.setUnderlineText(true);
            }
        }).append(LocaleController.getString(R.string.CdbVipBottomTips3)).append(LocaleController.getString(R.string.CdbVipBottomTips2) + LocaleController.getString(R.string.MemberServiceAgreement)).setClickSpan(new ClickableSpan() { // from class: im.uwrkaxlmjj.ui.hui.cdnvip.CdnVipCenterActivity.2
            @Override // android.text.style.ClickableSpan
            public void onClick(View widget) {
            }

            @Override // android.text.style.ClickableSpan, android.text.style.CharacterStyle
            public void updateDrawState(TextPaint ds) {
                ds.setColor(Theme.getColor(Theme.key_windowBackgroundWhiteGrayText3));
                ds.setUnderlineText(true);
            }
        }).create();
    }

    private void initRv(Context context) {
        this.rv.setLayoutManager(new GridLayoutManager(context, 2));
        PageSelectionAdapter<Integer, PageHolder> pageSelectionAdapter = new PageSelectionAdapter<Integer, PageHolder>(context) { // from class: im.uwrkaxlmjj.ui.hui.cdnvip.CdnVipCenterActivity.4
            @Override // im.uwrkaxlmjj.ui.hui.adapter.pageAdapter.PageSelectionAdapter
            public PageHolder onCreateViewHolderForChild(ViewGroup parent, int viewType) {
                return new PageHolder(LayoutInflater.from(getContext()).inflate(R.layout.item_cdb_vip_center, parent, false));
            }

            @Override // im.uwrkaxlmjj.ui.hui.adapter.pageAdapter.PageSelectionAdapter
            public void onBindViewHolderForChild(PageHolder holder, int position, Integer item) {
                String string;
                String string2;
                String string3;
                MryLinearLayout card = (MryLinearLayout) holder.itemView;
                card.setBorderColor(Theme.getColor(Theme.key_divider));
                card.setBorderWidth(1);
                card.setRadius(AndroidUtilities.dp(5.0f));
                card.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
                holder.setTextColorThemeGray(R.attr.tv1);
                holder.setTextColorThemeGray(R.attr.tv2);
                if (position == 0 || position == 1) {
                    holder.setGone(R.attr.tv2, false);
                    holder.setImageResId(R.attr.iv, position == 0 ? R.id.cv_center_tequan1 : R.id.cv_center_tequan2);
                    if (position == 0) {
                        string = LocaleController.getString(R.string.CdnVipTeQuan1);
                    } else {
                        string = LocaleController.getString(R.string.CdnVipTeQuan2);
                    }
                    holder.setText(R.attr.tv1, string);
                    if (position == 0) {
                        string2 = LocaleController.getString(R.string.CdnVipTeQuan1_1);
                    } else {
                        string2 = LocaleController.getString(R.string.CdnVipTeQuan2_1);
                    }
                    holder.setText(R.attr.tv2, string2);
                    return;
                }
                holder.setImageResId(R.attr.iv, position == 2 ? R.id.cv_center_tequan3 : R.id.cv_center_tequan4);
                if (position == 2) {
                    string3 = LocaleController.getString(R.string.CdnVipTeQuan3);
                } else {
                    string3 = LocaleController.getString(R.string.CdnVipTeQuan4);
                }
                holder.setText(R.attr.tv1, string3);
                holder.setGone(R.attr.tv2, true);
            }

            @Override // im.uwrkaxlmjj.ui.hui.adapter.pageAdapter.PageSelectionAdapter
            protected boolean isEnableForChild(PageHolder holder) {
                return false;
            }
        };
        this.adapter = pageSelectionAdapter;
        pageSelectionAdapter.setData(new ArrayList(Arrays.asList(0, 1, 2, 3)));
        this.rv.setAdapter(this.adapter);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void getUserCdnVipInfo() {
        TLRPCCdn.TL_getUserCdnVipInfo req = new TLRPCCdn.TL_getUserCdnVipInfo();
        final AlertDialog progressDialog = new AlertDialog(getParentActivity(), 3);
        progressDialog.setOnCancelListener(new DialogInterface.OnCancelListener() { // from class: im.uwrkaxlmjj.ui.hui.cdnvip.-$$Lambda$CdnVipCenterActivity$dmsVqSryPG8lzLTv_C37Pu2YCH0
            @Override // android.content.DialogInterface.OnCancelListener
            public final void onCancel(DialogInterface dialogInterface) {
                this.f$0.lambda$getUserCdnVipInfo$0$CdnVipCenterActivity(dialogInterface);
            }
        });
        progressDialog.show();
        int reqId = getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.hui.cdnvip.-$$Lambda$CdnVipCenterActivity$SNRv64B7fMmW282RM7d192mHCBA
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$getUserCdnVipInfo$1$CdnVipCenterActivity(progressDialog, tLObject, tL_error);
            }
        });
        getConnectionsManager().bindRequestToGuid(reqId, this.classGuid);
    }

    public /* synthetic */ void lambda$getUserCdnVipInfo$0$CdnVipCenterActivity(DialogInterface dialog) {
        getConnectionsManager().cancelRequestsForGuid(this.classGuid);
    }

    public /* synthetic */ void lambda$getUserCdnVipInfo$1$CdnVipCenterActivity(AlertDialog progressDialog, TLObject response, TLRPC.TL_error error) {
        parseCdnVipInfo(progressDialog, error, response, 0);
    }

    private void parseCdnVipInfo(final AlertDialog progressDialog, final TLRPC.TL_error error, final TLObject response, final int type) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.cdnvip.-$$Lambda$CdnVipCenterActivity$jR3bkFfAhkIZxdl8o1HqVGSku_g
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$parseCdnVipInfo$2$CdnVipCenterActivity(error, progressDialog, response, type);
            }
        });
    }

    public /* synthetic */ void lambda$parseCdnVipInfo$2$CdnVipCenterActivity(TLRPC.TL_error error, AlertDialog progressDialog, TLObject response, int type) {
        if (error != null) {
            if (progressDialog != null) {
                progressDialog.dismiss();
            }
            parseError(0, error.text);
            return;
        }
        if (response instanceof TLRPCCdn.TL_userCdnVipInfo) {
            try {
                this.cdnVipInfoBean = (CdnVipInfoBean) GsonUtils.fromJson(((TLRPCCdn.TL_userCdnVipInfo) response).vip_info.data, CdnVipInfoBean.class);
                setViewData();
                if (type == 0) {
                    getCdnVipUnitPrice(progressDialog);
                } else if (type == 1) {
                    if (progressDialog != null) {
                        progressDialog.dismiss();
                    }
                    WalletDialogUtil.showConfirmBtnWalletDialog(this, LocaleController.getString(R.string.AppCdnVipOpenSuccess), true, null, null);
                    getNotificationCenter().postNotificationName(NotificationCenter.cdnVipBuySuccess, new Object[0]);
                }
            } catch (Exception e) {
                e.printStackTrace();
                if (progressDialog != null) {
                    progressDialog.dismiss();
                }
                parseError(0, e.getMessage());
            }
        }
    }

    private void setViewData() {
        CdnVipInfoBean cdnVipInfoBean = this.cdnVipInfoBean;
        if (cdnVipInfoBean != null && cdnVipInfoBean.cdnVipIsAvailable()) {
            this.btn.setText(LocaleController.getString(R.string.SeeCdnVipDetails));
            this.tvVipTop.setBackgroundResource(R.id.cv_center_top_is_vip_true);
            this.tvVipTop.setTextColor(-5476835);
            this.tvStatusOrTime.setText(LocaleController.getString(R.string.AlreadyIsCdnVip));
            if (this.cdnVipInfoBean.isAutoPay()) {
                this.tvTips.setText(LocaleController.getString(R.string.CdnVipCenterTips2));
                return;
            }
            this.tvTips.setText(LocaleController.getString(R.string.CdnVipExpirationTime) + this.cdnVipInfoBean.getEndTimeFormat());
            return;
        }
        this.btn.setText(LocaleController.getString(R.string.OpenAppVIPNow));
        this.tvVipTop.setBackgroundResource(R.id.cv_center_top_is_vip_false);
        this.tvVipTop.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteGrayText3));
        this.tvStatusOrTime.setText(LocaleController.getString(R.string.ChooseTheOpeningTime));
        this.tvTips.setText(LocaleController.getString(R.string.CdnVipCenterTips));
    }

    private void getCdnVipUnitPrice(final AlertDialog progressDialog) {
        TLRPCFriendsHub.TL_GetOtherConfig req = new TLRPCFriendsHub.TL_GetOtherConfig();
        int reqId = getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.hui.cdnvip.-$$Lambda$CdnVipCenterActivity$coCE2sD0nSsyacpDHq7EAComnlU
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$getCdnVipUnitPrice$4$CdnVipCenterActivity(progressDialog, tLObject, tL_error);
            }
        });
        getConnectionsManager().bindRequestToGuid(reqId, this.classGuid);
    }

    public /* synthetic */ void lambda$getCdnVipUnitPrice$4$CdnVipCenterActivity(final AlertDialog progressDialog, final TLObject response, final TLRPC.TL_error error) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.cdnvip.-$$Lambda$CdnVipCenterActivity$E9odILAJoTYuxmrRLxp1B9Z5gtA
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$3$CdnVipCenterActivity(progressDialog, error, response);
            }
        });
    }

    public /* synthetic */ void lambda$null$3$CdnVipCenterActivity(AlertDialog progressDialog, TLRPC.TL_error error, TLObject response) {
        if (progressDialog != null) {
            progressDialog.dismiss();
        }
        if (error != null) {
            parseError(0, error.text);
            return;
        }
        TLRPCFriendsHub.TL_OtherConfig result = (TLRPCFriendsHub.TL_OtherConfig) response;
        try {
            if (result.data != null && !TextUtils.isEmpty(result.data.data)) {
                new JSONObject(result.data.data);
                CdnVipUnitPriceBean bean = (CdnVipUnitPriceBean) GsonUtils.fromJson(result.data.data, CdnVipUnitPriceBean.class);
                if (bean.getCdnPrice().size() > 0) {
                    this.cdnPrice = bean.getCdnPrice().get(0).getPriceStandard(0);
                    this.tvUnitPrice.setText("¥" + this.cdnPrice);
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
            parseError(0, e.getMessage());
        }
    }

    private void openCdnVip(String payPwd) {
        TLRPCCdn.TL_payCdnVip req = new TLRPCCdn.TL_payCdnVip();
        req.req_info = new TLRPC.TL_dataJSON();
        TLRPC.TL_dataJSON tL_dataJSON = req.req_info;
        String[] strArr = {"payformonth", "level", "paypassword"};
        Object[] objArr = new Object[3];
        objArr[0] = 1;
        CdnVipInfoBean cdnVipInfoBean = this.cdnVipInfoBean;
        objArr[1] = Integer.valueOf(cdnVipInfoBean != null ? cdnVipInfoBean.level : 1);
        objArr[2] = payPwd;
        tL_dataJSON.data = ParamsUtil.toJson(strArr, objArr);
        final AlertDialog progressDialog = new AlertDialog(getParentActivity(), 3);
        progressDialog.setOnCancelListener(new DialogInterface.OnCancelListener() { // from class: im.uwrkaxlmjj.ui.hui.cdnvip.-$$Lambda$CdnVipCenterActivity$PgPMdGtOnqGL5iGWV1Cw-mdVKYo
            @Override // android.content.DialogInterface.OnCancelListener
            public final void onCancel(DialogInterface dialogInterface) {
                this.f$0.lambda$openCdnVip$5$CdnVipCenterActivity(dialogInterface);
            }
        });
        progressDialog.show();
        int reqId = getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.hui.cdnvip.-$$Lambda$CdnVipCenterActivity$xTFzGI9sPqQOCpEOKPdKT36VOl0
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$openCdnVip$6$CdnVipCenterActivity(progressDialog, tLObject, tL_error);
            }
        });
        getConnectionsManager().bindRequestToGuid(reqId, this.classGuid);
    }

    public /* synthetic */ void lambda$openCdnVip$5$CdnVipCenterActivity(DialogInterface dialog) {
        getConnectionsManager().cancelRequestsForGuid(this.classGuid);
    }

    public /* synthetic */ void lambda$openCdnVip$6$CdnVipCenterActivity(AlertDialog progressDialog, TLObject response, TLRPC.TL_error error) {
        parseCdnVipInfo(progressDialog, error, response, 1);
    }

    private void getUserAccountInfo() {
        TLRPCWallet.TL_getPaymentAccountInfo req = new TLRPCWallet.TL_getPaymentAccountInfo();
        final AlertDialog progressDialog = new AlertDialog(getParentActivity(), 3);
        progressDialog.setOnCancelListener(new DialogInterface.OnCancelListener() { // from class: im.uwrkaxlmjj.ui.hui.cdnvip.-$$Lambda$CdnVipCenterActivity$W7MMSUEm5ioQIuzcq2qTIHOHS2k
            @Override // android.content.DialogInterface.OnCancelListener
            public final void onCancel(DialogInterface dialogInterface) {
                this.f$0.lambda$getUserAccountInfo$7$CdnVipCenterActivity(dialogInterface);
            }
        });
        progressDialog.show();
        getConnectionsManager().bindRequestToGuid(getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.hui.cdnvip.-$$Lambda$CdnVipCenterActivity$9zAf4wly1ChEOMz9ZSY1U1mJcNo
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$getUserAccountInfo$14$CdnVipCenterActivity(progressDialog, tLObject, tL_error);
            }
        }), this.classGuid);
    }

    public /* synthetic */ void lambda$getUserAccountInfo$7$CdnVipCenterActivity(DialogInterface dialog) {
        getConnectionsManager().cancelRequestsForGuid(this.classGuid);
    }

    public /* synthetic */ void lambda$getUserAccountInfo$14$CdnVipCenterActivity(final AlertDialog progressDialog, final TLObject response, final TLRPC.TL_error error) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.cdnvip.-$$Lambda$CdnVipCenterActivity$Oi4Q_wmHX-NdB9zI9dHMqGN8ZcU
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$13$CdnVipCenterActivity(progressDialog, error, response);
            }
        });
    }

    public /* synthetic */ void lambda$null$13$CdnVipCenterActivity(AlertDialog progressDialog, TLRPC.TL_error error, TLObject response) {
        if (progressDialog != null) {
            progressDialog.dismiss();
        }
        if (error != null) {
            parseError(error.code, error.text);
            return;
        }
        if (response instanceof TLRPCWallet.TL_paymentAccountInfoNotExist) {
            WalletDialogUtil.showWalletDialog(this, "", LocaleController.formatString("AccountInfoNotCompleted", R.string.AccountInfoNotCompleted, LocaleController.getString(R.string.BuyCdnVip), LocaleController.getString(R.string.Retry)), LocaleController.getString("Close", R.string.Close), LocaleController.getString("GoToWalletCenter", R.string.GoToWalletCenter), null, new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.cdnvip.-$$Lambda$CdnVipCenterActivity$FT8RGYiZHC1t7Awg806y8IOWkPw
                @Override // android.content.DialogInterface.OnClickListener
                public final void onClick(DialogInterface dialogInterface, int i) {
                    CdnVipCenterActivity.lambda$null$8(dialogInterface, i);
                }
            }, null);
            return;
        }
        TLApiModel<WalletAccountInfo> model = TLJsonResolve.parse(response, (Class<?>) WalletAccountInfo.class);
        if (model.isSuccess()) {
            WalletAccountInfo walletAccountInfo = model.model;
            this.accountInfo = walletAccountInfo;
            WalletConfigBean.setWalletAccountInfo(walletAccountInfo);
            WalletConfigBean.setConfigValue(model.model.getRiskList());
            if (this.accountInfo.isLocked()) {
                WalletDialogUtil.showWalletDialog(this, "", LocaleController.getString(R.string.PleaseContractServerToFindPayPasswordOrTryIt24HoursLater), LocaleController.getString(R.string.Close), LocaleController.getString(R.string.ContactCustomerService), null, new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.cdnvip.-$$Lambda$CdnVipCenterActivity$S3mQ6FyvXBsFhju94ncUNLJMeV4
                    @Override // android.content.DialogInterface.OnClickListener
                    public final void onClick(DialogInterface dialogInterface, int i) {
                        this.f$0.lambda$null$9$CdnVipCenterActivity(dialogInterface, i);
                    }
                }, null);
                return;
            }
            if (!this.accountInfo.hasNormalAuth()) {
                WalletDialogUtil.showWalletDialog(this, "", LocaleController.formatString("BankCardNotBindTips", R.string.BankCardNotBindTips, LocaleController.getString(R.string.BuyCdnVip)), LocaleController.getString("Close", R.string.Close), LocaleController.getString("GoToBind", R.string.GoToBind), null, new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.cdnvip.-$$Lambda$CdnVipCenterActivity$pWI3zpsm3kI0NHtRr8iJpZLx3Q0
                    @Override // android.content.DialogInterface.OnClickListener
                    public final void onClick(DialogInterface dialogInterface, int i) {
                        CdnVipCenterActivity.lambda$null$10(dialogInterface, i);
                    }
                }, null);
                return;
            }
            if (!this.accountInfo.hasBindBank()) {
                WalletDialogUtil.showWalletDialog(this, "", LocaleController.formatString("BankCardNotBindTips", R.string.BankCardNotBindTips, LocaleController.getString(R.string.BuyCdnVip)), LocaleController.getString("Close", R.string.Close), LocaleController.getString("GoToBind", R.string.GoToBind), null, new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.cdnvip.-$$Lambda$CdnVipCenterActivity$5t-aqdzudu6y52wUNReuNG5z7eE
                    @Override // android.content.DialogInterface.OnClickListener
                    public final void onClick(DialogInterface dialogInterface, int i) {
                        CdnVipCenterActivity.lambda$null$11(dialogInterface, i);
                    }
                }, null);
                return;
            } else if (!this.accountInfo.hasPaypassword()) {
                WalletDialogUtil.showWalletDialog(this, "", LocaleController.formatString("PayPasswordNotSetTips", R.string.PayPasswordNotSetTips, LocaleController.getString(R.string.BuyCdnVip)), LocaleController.getString("Close", R.string.Close), LocaleController.getString("redpacket_goto_set", R.string.redpacket_goto_set), null, new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.cdnvip.-$$Lambda$CdnVipCenterActivity$woDOAquyeQa0Io2qhitsv1IX9VE
                    @Override // android.content.DialogInterface.OnClickListener
                    public final void onClick(DialogInterface dialogInterface, int i) {
                        CdnVipCenterActivity.lambda$null$12(dialogInterface, i);
                    }
                }, null);
                return;
            } else {
                showPayPwdDialog();
                return;
            }
        }
        parseError(0, model.message);
    }

    static /* synthetic */ void lambda$null$8(DialogInterface dialogInterface, int i) {
    }

    public /* synthetic */ void lambda$null$9$CdnVipCenterActivity(DialogInterface dialogInterface, int i) {
        presentFragment(new AboutAppActivity());
    }

    static /* synthetic */ void lambda$null$10(DialogInterface dialogInterface, int i) {
    }

    static /* synthetic */ void lambda$null$11(DialogInterface dialogInterface, int i) {
    }

    static /* synthetic */ void lambda$null$12(DialogInterface dialogInterface, int i) {
    }

    private void showPayPwdDialog() {
        BottomSheet.Builder builder = new BottomSheet.Builder(getParentActivity());
        builder.setApplyTopPadding(false);
        builder.setApplyBottomPadding(false);
        View sheet = LayoutInflater.from(getParentActivity()).inflate(R.layout.layout_hongbao_pay_pwd, (ViewGroup) null, false);
        builder.setCustomView(sheet);
        ImageView ivAlertClose = (ImageView) sheet.findViewById(R.attr.ivAlertClose);
        ivAlertClose.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.cdnvip.-$$Lambda$CdnVipCenterActivity$YvWnsHYou7tlx3mhsLdldPaV2MQ
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$showPayPwdDialog$15$CdnVipCenterActivity(view);
            }
        });
        TextView tvTitle = (TextView) sheet.findViewById(R.attr.tvTitle);
        tvTitle.setText(LocaleController.getString("AppCdnVipServiceMothlySubscription", R.string.AppCdnVipServiceMothlySubscription));
        TextView tvShowMoneyView = (TextView) sheet.findViewById(R.attr.tvShowMoneyView);
        tvShowMoneyView.setTextColor(-109240);
        tvShowMoneyView.setText(DataTools.format2Decimals(this.cdnPrice));
        TextView tvMoneyUnit = (TextView) sheet.findViewById(R.attr.tvMoneyUnit);
        TextView tvPayMode = (TextView) sheet.findViewById(R.attr.tvPayMode);
        tvPayMode.setTextColor(-6710887);
        tvPayMode.setText(LocaleController.getString(R.string.HotCoinPay));
        TextView tvBlance = (TextView) sheet.findViewById(R.attr.tvBlance);
        SpanUtils spanTvBalance = SpanUtils.with(tvBlance);
        spanTvBalance.setVerticalAlign(2).append(LocaleController.getString(R.string.friendscircle_publish_remain)).setForegroundColor(-6710887).append(" (").setForegroundColor(-6710887);
        if (BuildVars.EDITION == 0) {
            spanTvBalance.append(NumberUtil.replacesSientificE(this.accountInfo.getCashAmount() / 100.0d, "#0.00"));
            tvMoneyUnit.setText(LocaleController.getString(R.string.HotCoin));
        } else {
            spanTvBalance.append(NumberUtil.replacesSientificE(this.accountInfo.getCashAmount() / 100.0d, "#0.00"));
            tvMoneyUnit.setText("CG");
        }
        spanTvBalance.setForegroundColor(-16777216).append(SQLBuilder.PARENTHESES_RIGHT).setForegroundColor(-6710887).create();
        TextView textView = (TextView) sheet.findViewById(R.attr.tvForgotPassword);
        this.tvForgotPassword = textView;
        textView.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.cdnvip.-$$Lambda$CdnVipCenterActivity$4bMucHcdEqo6TavjkY9taZPGvAM
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                CdnVipCenterActivity.lambda$showPayPwdDialog$16(view);
            }
        });
        this.llPayPassword = (LinearLayout) sheet.findViewById(R.attr.ll_pay_password);
        TextView[] textViewArr = new TextView[6];
        this.mTvPasswords = textViewArr;
        textViewArr[0] = (TextView) sheet.findViewById(R.attr.tv_password_1);
        this.mTvPasswords[1] = (TextView) sheet.findViewById(R.attr.tv_password_2);
        this.mTvPasswords[2] = (TextView) sheet.findViewById(R.attr.tv_password_3);
        this.mTvPasswords[3] = (TextView) sheet.findViewById(R.attr.tv_password_4);
        this.mTvPasswords[4] = (TextView) sheet.findViewById(R.attr.tv_password_5);
        this.mTvPasswords[5] = (TextView) sheet.findViewById(R.attr.tv_password_6);
        GridView gvKeyboard = (GridView) sheet.findViewById(R.attr.gvKeyboard);
        gvKeyboard.setAdapter((ListAdapter) new KeyboardAdapter(this.mNumbers, getParentActivity()));
        gvKeyboard.setOnItemClickListener(new AdapterView.OnItemClickListener() { // from class: im.uwrkaxlmjj.ui.hui.cdnvip.-$$Lambda$CdnVipCenterActivity$vZJjAcliFDoLnIaXLJ8fdNiKgpY
            @Override // android.widget.AdapterView.OnItemClickListener
            public final void onItemClick(AdapterView adapterView, View view, int i, long j) {
                this.f$0.lambda$showPayPwdDialog$17$CdnVipCenterActivity(adapterView, view, i, j);
            }
        });
        Dialog dialog = showDialog(builder.create());
        dialog.setOnDismissListener(new DialogInterface.OnDismissListener() { // from class: im.uwrkaxlmjj.ui.hui.cdnvip.-$$Lambda$CdnVipCenterActivity$4YfshPmEOsicYjXZvD3nFWRmFBs
            @Override // android.content.DialogInterface.OnDismissListener
            public final void onDismiss(DialogInterface dialogInterface) {
                this.f$0.lambda$showPayPwdDialog$18$CdnVipCenterActivity(dialogInterface);
            }
        });
    }

    public /* synthetic */ void lambda$showPayPwdDialog$15$CdnVipCenterActivity(View v) {
        dismissCurrentDialog();
    }

    static /* synthetic */ void lambda$showPayPwdDialog$16(View v) {
    }

    public /* synthetic */ void lambda$showPayPwdDialog$17$CdnVipCenterActivity(AdapterView parent, View view, int position, long id) {
        if (position < 9 || position == 10) {
            int i = this.notEmptyTvCount;
            TextView[] textViewArr = this.mTvPasswords;
            if (i == textViewArr.length) {
                return;
            }
            int length = textViewArr.length;
            int i2 = 0;
            while (true) {
                if (i2 >= length) {
                    break;
                }
                TextView textView = textViewArr[i2];
                if (!TextUtils.isEmpty(textView.getText())) {
                    i2++;
                } else {
                    textView.setText(String.valueOf(this.mNumbers.get(position)));
                    this.notEmptyTvCount++;
                    break;
                }
            }
            if (this.notEmptyTvCount == this.mTvPasswords.length) {
                StringBuilder password = new StringBuilder();
                for (TextView textView2 : this.mTvPasswords) {
                    String text = textView2.getText().toString();
                    if (!TextUtils.isEmpty(text)) {
                        password.append(text);
                    }
                }
                String encrypt = AesUtils.encrypt(password.toString().trim());
                openCdnVip(encrypt);
                return;
            }
            return;
        }
        if (position == 11) {
            for (int i3 = this.mTvPasswords.length - 1; i3 >= 0; i3--) {
                if (!TextUtils.isEmpty(this.mTvPasswords[i3].getText())) {
                    this.mTvPasswords[i3].setText((CharSequence) null);
                    this.notEmptyTvCount--;
                    return;
                }
            }
        }
    }

    public /* synthetic */ void lambda$showPayPwdDialog$18$CdnVipCenterActivity(DialogInterface dialog1) {
        this.notEmptyTvCount = 0;
    }

    @OnClick({R.attr.btn})
    void onClick(View v) {
        CdnVipInfoBean cdnVipInfoBean = this.cdnVipInfoBean;
        if (cdnVipInfoBean != null) {
            if (cdnVipInfoBean.cdnVipIsAvailable()) {
                presentFragment(new CdnVipDetailsActivity(this.cdnVipInfoBean).setDelegate(this));
            } else if (!TextUtils.isEmpty(this.cdnPrice)) {
                getUserAccountInfo();
            }
        }
    }

    private void parseError(int errorCode, String errorMsg) {
        WalletDialogUtil.showConfirmBtnWalletDialog(this, WalletErrorUtil.getErrorDescription(errorMsg));
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onFragmentDestroy() {
        super.onFragmentDestroy();
    }

    @Override // im.uwrkaxlmjj.ui.hui.cdnvip.CdnVipDetailsActivity.Delegate
    public void onResult(CdnVipInfoBean cdnVipInfoBean) {
        if (cdnVipInfoBean != null) {
            this.cdnVipInfoBean = cdnVipInfoBean;
            setViewData();
        }
    }
}
