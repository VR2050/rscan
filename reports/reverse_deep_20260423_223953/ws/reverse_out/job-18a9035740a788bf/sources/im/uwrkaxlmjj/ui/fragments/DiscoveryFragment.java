package im.uwrkaxlmjj.ui.fragments;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Context;
import android.content.DialogInterface;
import android.location.LocationManager;
import android.os.Build;
import android.os.Bundle;
import android.provider.Settings;
import android.text.TextUtils;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.EditText;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.Toast;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import com.alibaba.fastjson.JSONObject;
import com.bjz.comm.net.utils.RxHelper;
import com.blankj.utilcode.util.ScreenUtils;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.ApplicationLoader;
import im.uwrkaxlmjj.messenger.FileLog;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.NotificationCenter;
import im.uwrkaxlmjj.messenger.UserConfig;
import im.uwrkaxlmjj.tgnet.ConnectionsManager;
import im.uwrkaxlmjj.tgnet.RequestDelegate;
import im.uwrkaxlmjj.tgnet.TLObject;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.tgnet.TLRPC2;
import im.uwrkaxlmjj.tgnet.TLRPCWallet;
import im.uwrkaxlmjj.ui.WebviewActivity;
import im.uwrkaxlmjj.ui.actionbar.ActionBar;
import im.uwrkaxlmjj.ui.actionbar.ActionBarMenu;
import im.uwrkaxlmjj.ui.actionbar.AlertDialog;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.cells.ShadowSectionCell;
import im.uwrkaxlmjj.ui.components.LayoutHelper;
import im.uwrkaxlmjj.ui.components.RecyclerListView;
import im.uwrkaxlmjj.ui.components.banner.Banner;
import im.uwrkaxlmjj.ui.components.banner.adapter.BannerAdapter;
import im.uwrkaxlmjj.ui.components.banner.indicator.RectangleIndicator;
import im.uwrkaxlmjj.ui.components.banner.listener.OnBannerListener;
import im.uwrkaxlmjj.ui.components.toast.ToastUtils;
import im.uwrkaxlmjj.ui.constants.Constants;
import im.uwrkaxlmjj.ui.hcells.IndexTextCell;
import im.uwrkaxlmjj.ui.hui.adapter.pageAdapter.PageHolder;
import im.uwrkaxlmjj.ui.hui.discovery.ActionIntroActivity;
import im.uwrkaxlmjj.ui.hui.discovery.NearPersonAndGroupActivity;
import im.uwrkaxlmjj.ui.hui.discovery.QrScanActivity;
import im.uwrkaxlmjj.ui.hui.discoveryweb.DiscoveryJumpToPage;
import im.uwrkaxlmjj.ui.hui.friendscircle.glide.GlideUtils;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.FriendsCircleActivity;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.FcAlbumActivity;
import im.uwrkaxlmjj.ui.hui.hotGroup.HotGroupRecommendActivity;
import im.uwrkaxlmjj.ui.hui.visualcall.PermissionUtils;
import im.uwrkaxlmjj.ui.hviews.sliding.SlidingLayout;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class DiscoveryFragment extends BaseFmts implements Constants {
    private static final String TAG = "DiscoveryFragment";
    private static final int refresh = 5;
    private Delegate delegate;
    EditText editText;
    private int extraDataReqToken;
    private boolean hasGps;
    private ListAdapter listAdapter;
    private RecyclerListView listView;
    private onRefreshMainInterface mainInterface;
    private AlertDialog progressDialog;
    private int rowCount;
    private int startSectionRow = -1;
    private int bannerStartRow = -1;
    private int bannerRow = -1;
    private int bannerEndRow = -1;
    private int friendsHubRow = -1;
    private int friendsHubEmptyRow = -1;
    private int scanRow = -1;
    private int nearbyRow = -1;
    private int nearbyEmptyRow = -1;
    private int gameCenterRow = -1;
    private int gameCenterEmptyRow = -1;
    private int miniProgramRow = -1;
    private int lastSectionRow = -1;
    private int album = -1;
    private int albumEmptyRow = -1;
    private int recommendChannel = -1;
    private int recommendChannelEmptyRow = -1;
    private int extraDataStartRow = -1;
    private int extraDataEndRow = -1;

    public interface Delegate {
        TLRPC2.TL_DiscoveryPageSetting getDiscoveryPageData();
    }

    public DiscoveryFragment(onRefreshMainInterface mainInterface) {
        this.mainInterface = mainInterface;
    }

    @Override // im.uwrkaxlmjj.ui.fragments.BaseFmts, androidx.fragment.app.Fragment
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        try {
            this.hasGps = ApplicationLoader.applicationContext.getPackageManager().hasSystemFeature("android.hardware.location.gps");
        } catch (Throwable th) {
            this.hasGps = false;
        }
        updateRow();
    }

    @Override // im.uwrkaxlmjj.ui.fragments.BaseFmts, androidx.fragment.app.Fragment
    public View onCreateView(LayoutInflater inflater, ViewGroup container, Bundle savedInstanceState) {
        FrameLayout frameLayout = new FrameLayout(this.context);
        this.fragmentView = frameLayout;
        this.actionBar = createActionBar();
        this.actionBar.setAllowOverlayTitle(true);
        this.actionBar.setTitle(LocaleController.getString("Discovery", R.string.Discovery));
        ActionBarMenu menu = this.actionBar.createMenu();
        menu.addItem(5, LocaleController.getString("Refresh", R.string.Refresh));
        this.actionBar.setActionBarMenuOnItemClick(new ActionBar.ActionBarMenuOnItemClick() { // from class: im.uwrkaxlmjj.ui.fragments.DiscoveryFragment.1
            @Override // im.uwrkaxlmjj.ui.actionbar.ActionBar.ActionBarMenuOnItemClick
            public void onItemClick(int id) {
                if (id == 5 && DiscoveryFragment.this.mainInterface != null) {
                    DiscoveryFragment.this.mainInterface.onRefreshMain();
                }
            }
        });
        frameLayout.addView(this.actionBar, LayoutHelper.createFrame(-1, -2.0f));
        SlidingLayout root = new SlidingLayout(this.context);
        root.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundGray));
        frameLayout.addView(root, LayoutHelper.createFrameWithActionBar(-1, -1));
        RecyclerListView recyclerListView = new RecyclerListView(this.context);
        this.listView = recyclerListView;
        recyclerListView.setClipToPadding(false);
        this.listView.setClipChildren(false);
        this.listView.setVerticalScrollBarEnabled(false);
        this.listView.setLayoutManager(new LinearLayoutManager(this.context, 1, false));
        root.addView(this.listView, LayoutHelper.createFrame(-1, -1.0f));
        View headerShadow = new View(this.context);
        headerShadow.setBackground(getResources().getDrawable(R.drawable.header_shadow).mutate());
        frameLayout.addView(headerShadow, LayoutHelper.createFrameWithActionBar(-1, 1));
        ListAdapter listAdapter = new ListAdapter(this.context);
        this.listAdapter = listAdapter;
        this.listView.setAdapter(listAdapter);
        this.listView.setOnItemClickListener(new RecyclerListView.OnItemClickListener() { // from class: im.uwrkaxlmjj.ui.fragments.-$$Lambda$DiscoveryFragment$ms-iHMZ6Pt4EvBQ3GGD5bqrydEM
            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.OnItemClickListener
            public final void onItemClick(View view, int i) {
                this.f$0.lambda$onCreateView$0$DiscoveryFragment(view, i);
            }
        });
        return this.fragmentView;
    }

    public /* synthetic */ void lambda$onCreateView$0$DiscoveryFragment(View view, int position) {
        Activity activity;
        if (position == this.nearbyRow && this.hasGps) {
            if (Build.VERSION.SDK_INT >= 23 && (activity = getParentActivity()) != null && activity.checkSelfPermission(PermissionUtils.PERMISSION_ACCESS_COARSE_LOCATION) != 0) {
                presentFragment(new ActionIntroActivity(1));
                return;
            }
            boolean enabled = true;
            if (Build.VERSION.SDK_INT >= 28) {
                LocationManager lm = (LocationManager) ApplicationLoader.applicationContext.getSystemService("location");
                enabled = lm.isLocationEnabled();
            } else if (Build.VERSION.SDK_INT >= 19) {
                try {
                    int mode = Settings.Secure.getInt(ApplicationLoader.applicationContext.getContentResolver(), "location_mode", 0);
                    enabled = mode != 0;
                } catch (Throwable e) {
                    FileLog.e(e);
                }
                presentFragment(new NearPersonAndGroupActivity());
            } else if (position != this.miniProgramRow) {
                if (position == this.scanRow) {
                    presentFragment(new QrScanActivity());
                } else if (((Integer) view.getTag()).intValue() != position) {
                    ToastUtils.show(R.string.NotSupport);
                }
            }
            if (!enabled) {
                presentFragment(new ActionIntroActivity(4));
                return;
            } else {
                presentFragment(new NearPersonAndGroupActivity());
                return;
            }
        }
        if (position != this.miniProgramRow) {
            if (position == this.friendsHubRow) {
                presentFragment(new FriendsCircleActivity());
                NotificationCenter.getGlobalInstance().postNotificationName(NotificationCenter.userFriendsCircleUpdate, new Object[0]);
                return;
            }
            if (position != this.gameCenterRow) {
                if (position == this.scanRow) {
                    presentFragment(new QrScanActivity());
                    return;
                }
                if (position == this.album) {
                    presentFragment(new FcAlbumActivity());
                    return;
                }
                if (position == this.recommendChannel) {
                    if (getUserConfig().isClientActivated()) {
                        presentFragment(new HotGroupRecommendActivity());
                        return;
                    }
                    return;
                }
                int i = this.extraDataStartRow;
                if (i != -1 && position > i && position < this.extraDataEndRow) {
                    int cpo = (position - i) - 1;
                    Delegate delegate = this.delegate;
                    if (delegate != null && delegate.getDiscoveryPageData() != null) {
                        gotoDiscoveryJumpToPage(cpo);
                        return;
                    }
                    return;
                }
                if (!(view instanceof ShadowSectionCell)) {
                    ToastUtils.show(R.string.NotSupport);
                }
            }
        }
    }

    private void gotoDiscoveryJumpToPage(int cpo) {
        TLRPC2.TL_DiscoveryPageSetting_SM s;
        if (cpo < 0 || cpo >= this.delegate.getDiscoveryPageData().getS().size() || (s = this.delegate.getDiscoveryPageData().getS().get(cpo)) == null) {
            return;
        }
        if (TextUtils.isEmpty(s.getUrl())) {
            getExtraDataLoginUrl(s);
        } else if (!TextUtils.isEmpty(s.getUrl()) && (s.getUrl().startsWith("http:") || s.getUrl().startsWith("https:"))) {
            presentFragment(DiscoveryJumpToPage.toPage(s.getTitle(), s.getUrl()));
        } else {
            ToastUtils.show(R.string.CancelLinkExpired);
        }
    }

    private void showInputDialog(final int cpo) {
        EditText editText = new EditText(this.context);
        this.editText = editText;
        editText.setHintTextColor(Theme.getColor(Theme.key_windowBackgroundGrayText));
        this.editText.setInputType(163840);
        AlertDialog.Builder inputDialog = new AlertDialog.Builder(this.context);
        inputDialog.setTitle("输入小程序码").setView(this.editText);
        inputDialog.setNegativeButton("取消", new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.fragments.DiscoveryFragment.2
            @Override // android.content.DialogInterface.OnClickListener
            public void onClick(DialogInterface dialog, int which) {
                dialog.dismiss();
            }
        });
        inputDialog.setPositiveButton("确定", (DialogInterface.OnClickListener) null);
        final android.app.AlertDialog dialog = inputDialog.create();
        if (dialog != null) {
            dialog.setCanceledOnTouchOutside(false);
            dialog.setCancelable(false);
        }
        dialog.show();
        dialog.getButton(-1).setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.fragments.DiscoveryFragment.3
            @Override // android.view.View.OnClickListener
            public void onClick(View v) {
                String input = DiscoveryFragment.this.editText.getText().toString();
                if (!input.equals("")) {
                    DiscoveryFragment.this.TL_paymentTrans(dialog, cpo);
                    return;
                }
                Toast.makeText(DiscoveryFragment.this.context, "内容不能为空！" + input, 1).show();
            }
        });
    }

    private void needShowProgress() {
        im.uwrkaxlmjj.ui.actionbar.AlertDialog alertDialog = new im.uwrkaxlmjj.ui.actionbar.AlertDialog(this.context, 3);
        this.progressDialog = alertDialog;
        alertDialog.setCanCancel(true);
        this.progressDialog.show();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void TL_paymentTrans(final android.app.AlertDialog dialog, final int cpo) {
        TLRPC2.TL_DiscoveryPageSetting_SM s = this.delegate.getDiscoveryPageData().getS().get(cpo);
        if (s == null) {
            return;
        }
        TLRPCWallet.TL_paymentTrans req = new TLRPCWallet.TL_paymentTrans();
        JSONObject jsonObject = new JSONObject();
        jsonObject.put("businessKey", (Object) "check_communication_code");
        jsonObject.put("tag", (Object) "Sbcc");
        jsonObject.put("link", (Object) s.getUrl());
        jsonObject.put("code", (Object) this.editText.getText().toString().trim());
        req.data.data = jsonObject.toJSONString();
        needShowProgress();
        Log.e("debug", "request===" + jsonObject.toJSONString());
        ConnectionsManager.getInstance(UserConfig.selectedAccount).sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.fragments.-$$Lambda$DiscoveryFragment$AhxgQluOul2DR4E9MSy2mMYqwIg
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$TL_paymentTrans$2$DiscoveryFragment(dialog, cpo, tLObject, tL_error);
            }
        }, 10);
    }

    public /* synthetic */ void lambda$TL_paymentTrans$2$DiscoveryFragment(final android.app.AlertDialog dialog, final int cpo, final TLObject response, final TLRPC.TL_error error) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.fragments.-$$Lambda$DiscoveryFragment$kYzlzaXs98zDYwQMKMpqxUkKGyU
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$1$DiscoveryFragment(error, response, dialog, cpo);
            }
        });
    }

    public /* synthetic */ void lambda$null$1$DiscoveryFragment(TLRPC.TL_error error, TLObject response, android.app.AlertDialog dialog, int cpo) {
        if (error == null) {
            Log.e("debug", "password_setting response===" + JSONObject.toJSONString(((TLRPCWallet.TL_paymentTransResult) response).data));
            this.progressDialog.dismiss();
            JSONObject data = (JSONObject) JSONObject.parse(JSONObject.toJSONString(((TLRPCWallet.TL_paymentTransResult) response).data));
            JSONObject resp = (JSONObject) JSONObject.parse(data.getString("data"));
            if (resp.getInteger("code").intValue() == 0) {
                dialog.cancel();
                gotoDiscoveryJumpToPage(cpo);
                return;
            } else {
                if (resp.getInteger("code").intValue() == 400) {
                    ToastUtils.show((CharSequence) "验证码错误");
                    return;
                }
                ToastUtils.show((CharSequence) (LocaleController.getString("text_system_error", R.string.text_system_error) + resp.getString("codeMsg")));
                return;
            }
        }
        this.progressDialog.dismiss();
        ToastUtils.show((CharSequence) (LocaleController.getString("text_system_error", R.string.text_system_error) + error.text));
    }

    @Override // im.uwrkaxlmjj.ui.fragments.BaseFmts
    protected void lazyLoadData() {
        super.lazyLoadData();
    }

    private void updateRow() {
        this.rowCount = 0;
        this.rowCount = 0 + 1;
        this.bannerStartRow = 0;
        Delegate delegate = this.delegate;
        if (delegate != null && delegate.getDiscoveryPageData() != null && this.delegate.getDiscoveryPageData().getG().size() > 0) {
            int i = this.rowCount;
            int i2 = i + 1;
            this.rowCount = i2;
            this.bannerRow = i;
            this.rowCount = i2 + 1;
            this.bannerEndRow = i2;
        }
        int i3 = this.rowCount;
        this.rowCount = i3 + 1;
        this.scanRow = i3;
        Delegate delegate2 = this.delegate;
        if (delegate2 != null && delegate2.getDiscoveryPageData() != null && this.delegate.getDiscoveryPageData().getS().size() > 0) {
            int i4 = this.rowCount;
            int i5 = i4 + 1;
            this.rowCount = i5;
            this.extraDataStartRow = i4;
            int size = i5 + this.delegate.getDiscoveryPageData().getS().size();
            this.rowCount = size;
            this.rowCount = size + 1;
            this.extraDataEndRow = size;
        }
        int i6 = this.rowCount;
        this.rowCount = i6 + 1;
        this.lastSectionRow = i6;
        ListAdapter listAdapter = this.listAdapter;
        if (listAdapter != null) {
            listAdapter.notifyDataSetChanged();
        }
    }

    private void getExtraDataLoginUrl(final TLRPC2.TL_DiscoveryPageSetting_SM s) {
        if (s == null || TextUtils.isEmpty(s.getTitle()) || this.extraDataReqToken != 0) {
            return;
        }
        TLRPC2.TL_GetLoginUrl req = new TLRPC2.TL_GetLoginUrl();
        req.app_code = s.getTitle();
        this.extraDataReqToken = getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.fragments.-$$Lambda$DiscoveryFragment$hR-HBqBLIFLep-E2XI_DcrEahIs
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$getExtraDataLoginUrl$4$DiscoveryFragment(s, tLObject, tL_error);
            }
        });
    }

    public /* synthetic */ void lambda$getExtraDataLoginUrl$4$DiscoveryFragment(final TLRPC2.TL_DiscoveryPageSetting_SM s, final TLObject response, final TLRPC.TL_error error) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.fragments.-$$Lambda$DiscoveryFragment$YwoyFZ9n2vevjIX-OZvQ-ybxaEQ
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$3$DiscoveryFragment(error, response, s);
            }
        });
    }

    public /* synthetic */ void lambda$null$3$DiscoveryFragment(TLRPC.TL_error error, TLObject response, TLRPC2.TL_DiscoveryPageSetting_SM s) {
        String str;
        if (error == null && (response instanceof TLRPC2.TL_LoginUrlInfo)) {
            TLRPC2.TL_LoginUrlInfo res = (TLRPC2.TL_LoginUrlInfo) response;
            String url = res.url;
            if (!TextUtils.isEmpty(url) && (url.startsWith("http:") || url.startsWith("https:"))) {
                presentFragment(DiscoveryJumpToPage.toPage(s.getTitle(), url));
            } else {
                ToastUtils.show(R.string.CancelLinkExpired);
            }
        } else {
            ToastUtils.show(R.string.FailedToGetLink);
            StringBuilder sb = new StringBuilder();
            sb.append("DiscoveryFragment getExtraDataLoginUrl error: ");
            if (error != null) {
                str = "errCode:" + error.code + ", errText:" + error.text;
            } else {
                str = "error is null";
            }
            sb.append(str);
            FileLog.e(sb.toString());
        }
        this.extraDataReqToken = 0;
    }

    public void setDelegate(Delegate delegate) {
        this.delegate = delegate;
    }

    @Override // androidx.fragment.app.Fragment
    public void onResume() {
        super.onResume();
    }

    @Override // im.uwrkaxlmjj.ui.fragments.BaseFmts, androidx.fragment.app.Fragment
    public void onDestroy() {
        RxHelper.getInstance().lambda$sendSimpleRequest$0$RxHelper(getClass().getSimpleName());
        if (this.extraDataReqToken != 0) {
            getConnectionsManager().cancelRequest(this.extraDataReqToken, false);
            this.extraDataReqToken = 0;
        }
        super.onDestroy();
    }

    /* JADX INFO: Access modifiers changed from: private */
    class ListAdapter extends RecyclerListView.SelectionAdapter {
        private Context mContext;

        public ListAdapter(Context context) {
            this.mContext = context;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemCount() {
            return DiscoveryFragment.this.rowCount;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void onBindViewHolder(RecyclerView.ViewHolder holder, int position) {
            int itemViewType = holder.getItemViewType();
            if (itemViewType != 0) {
                if (itemViewType == 1) {
                    View view = new View(this.mContext);
                    RecyclerView.LayoutParams layoutParams = new RecyclerView.LayoutParams(-1, AndroidUtilities.dp(10.0f));
                    view.setLayoutParams(layoutParams);
                    return;
                }
                if (itemViewType != 2) {
                    if (itemViewType == 3) {
                        View view2 = new View(this.mContext);
                        RecyclerView.LayoutParams layoutParams2 = new RecyclerView.LayoutParams(-1, AndroidUtilities.dp(15.0f));
                        view2.setLayoutParams(layoutParams2);
                        return;
                    }
                    return;
                }
                View view3 = holder.itemView;
                Banner<TLRPC2.TL_DiscoveryPageSetting_GM, BannerAdapter<TLRPC2.TL_DiscoveryPageSetting_GM, PageHolder>> banner = (Banner) view3;
                BannerAdapter<TLRPC2.TL_DiscoveryPageSetting_GM, PageHolder> adapter = banner.getAdapter();
                if (banner.getAdapter() == null) {
                    adapter = new BannerAdapter<TLRPC2.TL_DiscoveryPageSetting_GM, PageHolder>(null) { // from class: im.uwrkaxlmjj.ui.fragments.DiscoveryFragment.ListAdapter.1
                        @Override // im.uwrkaxlmjj.ui.components.banner.holder.IViewHolder
                        public PageHolder onCreateHolder(ViewGroup parent, int viewType) {
                            ImageView iv = new ImageView(DiscoveryFragment.this.getParentActivity());
                            iv.setScaleType(ImageView.ScaleType.FIT_XY);
                            RecyclerView.LayoutParams lp = new RecyclerView.LayoutParams(-1, -1);
                            iv.setLayoutParams(lp);
                            return new PageHolder(iv);
                        }

                        @Override // im.uwrkaxlmjj.ui.components.banner.holder.IViewHolder
                        public void onBindView(PageHolder holder2, TLRPC2.TL_DiscoveryPageSetting_GM data, int position2, int size) {
                            ImageView iv = (ImageView) holder2.itemView;
                            GlideUtils.getInstance().load(data.getPic(), iv.getContext(), iv, R.id.banner_discovery1);
                        }
                    };
                    banner.setAdapter(adapter);
                }
                banner.setOnBannerListener(new OnBannerListener() { // from class: im.uwrkaxlmjj.ui.fragments.-$$Lambda$DiscoveryFragment$ListAdapter$zIdEnowiEgnWih99_XlA1yE7veU
                    @Override // im.uwrkaxlmjj.ui.components.banner.listener.OnBannerListener
                    public final void OnBannerClick(Object obj, int i) {
                        this.f$0.lambda$onBindViewHolder$0$DiscoveryFragment$ListAdapter((TLRPC2.TL_DiscoveryPageSetting_GM) obj, i);
                    }
                });
                if (DiscoveryFragment.this.delegate != null && DiscoveryFragment.this.delegate.getDiscoveryPageData() != null) {
                    adapter.setDatas(DiscoveryFragment.this.delegate.getDiscoveryPageData().getG());
                }
                adapter.notifyDataSetChanged();
                return;
            }
            if (position != DiscoveryFragment.this.friendsHubRow) {
                if (position != DiscoveryFragment.this.scanRow) {
                    if (position != DiscoveryFragment.this.nearbyRow) {
                        if (position != DiscoveryFragment.this.miniProgramRow) {
                            if (position != DiscoveryFragment.this.gameCenterRow) {
                                if (position != DiscoveryFragment.this.album) {
                                    if (position != DiscoveryFragment.this.recommendChannel) {
                                        if (position > DiscoveryFragment.this.extraDataStartRow && position < DiscoveryFragment.this.extraDataEndRow) {
                                            int cpo = (position - DiscoveryFragment.this.extraDataStartRow) - 1;
                                            if (DiscoveryFragment.this.delegate != null && DiscoveryFragment.this.delegate.getDiscoveryPageData() != null && cpo >= 0 && cpo < DiscoveryFragment.this.delegate.getDiscoveryPageData().getS().size()) {
                                                try {
                                                    TLRPC2.TL_DiscoveryPageSetting_SM item = DiscoveryFragment.this.delegate.getDiscoveryPageData().getS().get(cpo);
                                                    ((IndexTextCell) holder.itemView).setTextAndIcon(item.getTitle(), item.getLogo(), AndroidUtilities.dp(7.0f), 0, cpo == DiscoveryFragment.this.extraDataEndRow - 1);
                                                    return;
                                                } catch (Exception e) {
                                                    return;
                                                }
                                            }
                                            return;
                                        }
                                        return;
                                    }
                                    ((IndexTextCell) holder.itemView).setTextAndIcon(LocaleController.getString("HotChannelRecommend", R.string.HotChannelRecommend), R.id.ic_fire, R.id.icon_arrow_right, false);
                                    return;
                                }
                                ((IndexTextCell) holder.itemView).setTextAndIcon(LocaleController.getString("MyAlbum", R.string.MyAlbum), R.drawable.fmt_discoveryv2_album, R.id.icon_arrow_right, false);
                                return;
                            }
                            ((IndexTextCell) holder.itemView).setTextAndIcon(LocaleController.getString("GameCenter", R.string.GameCenter), R.id.fmt_discovery_games, R.id.icon_arrow_right, false);
                            return;
                        }
                        ((IndexTextCell) holder.itemView).setTextAndIcon(LocaleController.getString("MiniProgram", R.string.MiniProgram), R.id.fmt_discovery_mini_program, R.id.icon_arrow_right, false);
                        return;
                    }
                    ((IndexTextCell) holder.itemView).setTextAndIcon(LocaleController.getString("PeopleNearby", R.string.PeopleNearby), R.drawable.fmt_discoveryv2_nearby, R.id.icon_arrow_right, false);
                    return;
                }
                ((IndexTextCell) holder.itemView).setTextAndIcon(LocaleController.getString("Scan", R.string.Scan), R.drawable.fmt_discoveryv2_scan, R.id.icon_arrow_right, false);
                return;
            }
            ((IndexTextCell) holder.itemView).setTextAndIcon(LocaleController.getString("FriendHub", R.string.FriendHub), R.drawable.fmt_discoveryv2_friends_hub, R.id.icon_arrow_right, false);
        }

        public /* synthetic */ void lambda$onBindViewHolder$0$DiscoveryFragment$ListAdapter(TLRPC2.TL_DiscoveryPageSetting_GM data, int position1) {
            DiscoveryFragment.this.presentFragment(new WebviewActivity(data.getUrl(), (String) null));
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SelectionAdapter
        public boolean isEnabled(RecyclerView.ViewHolder holder) {
            int position = holder.getAdapterPosition();
            return position == DiscoveryFragment.this.friendsHubRow || position == DiscoveryFragment.this.scanRow || position == DiscoveryFragment.this.nearbyRow || position == DiscoveryFragment.this.gameCenterRow || position == DiscoveryFragment.this.miniProgramRow || position == DiscoveryFragment.this.album || position == DiscoveryFragment.this.recommendChannel || (DiscoveryFragment.this.extraDataStartRow > 0 && position > DiscoveryFragment.this.extraDataStartRow && position < DiscoveryFragment.this.extraDataEndRow);
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public RecyclerView.ViewHolder onCreateViewHolder(ViewGroup viewGroup, int i) {
            View view;
            if (i == 1 || i == 3) {
                ShadowSectionCell shadowSectionCell = i == 1 ? new ShadowSectionCell(this.mContext) : new ShadowSectionCell(this.mContext, 15);
                shadowSectionCell.setLayoutParams(new RecyclerView.LayoutParams(-1, -2));
                view = shadowSectionCell;
            } else if (i == 2) {
                Banner banner = new Banner(DiscoveryFragment.this.getContext());
                banner.setBannerRound(AndroidUtilities.dp(10.0f));
                banner.setLoopTime(6000L);
                int iDp = AndroidUtilities.dp(2.0f);
                RectangleIndicator rectangleIndicator = new RectangleIndicator(DiscoveryFragment.this.getContext());
                rectangleIndicator.setPadding(iDp, iDp, iDp, iDp);
                rectangleIndicator.setBackground(Theme.createRoundRectDrawable(AndroidUtilities.dp(5.0f), AndroidUtilities.alphaColor(0.5f, -1)));
                banner.setIndicator(rectangleIndicator).setIndicatorNormalWidth(AndroidUtilities.dp(6.0f)).setIndicatorHeight(AndroidUtilities.dp(6.0f)).setIndicatorSpace(AndroidUtilities.dp(5.0f)).setIndicatorSelectedWidth(AndroidUtilities.dp(15.0f)).setIndicatorRadius(AndroidUtilities.dp(6.0f)).setIndicatorSelectedColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlueButton)).setIndicatorNormalColor(-1);
                RecyclerView.LayoutParams layoutParams = new RecyclerView.LayoutParams(-1, (int) ((ScreenUtils.getScreenWidth() - AndroidUtilities.dp(30.0f)) / 3.45f));
                layoutParams.leftMargin = AndroidUtilities.dp(15.0f);
                layoutParams.rightMargin = AndroidUtilities.dp(15.0f);
                banner.setLayoutParams(layoutParams);
                banner.setClipToPadding(false);
                banner.setClipChildren(false);
                view = banner;
            } else {
                IndexTextCell indexTextCell = new IndexTextCell(this.mContext);
                indexTextCell.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
                indexTextCell.setLayoutParams(new RecyclerView.LayoutParams(-1, -2));
                view = indexTextCell;
            }
            return new RecyclerListView.Holder(view);
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemViewType(int position) {
            if (position != DiscoveryFragment.this.friendsHubEmptyRow && position != DiscoveryFragment.this.nearbyEmptyRow && position != DiscoveryFragment.this.gameCenterEmptyRow && position != DiscoveryFragment.this.lastSectionRow && position != DiscoveryFragment.this.startSectionRow && position != DiscoveryFragment.this.albumEmptyRow && position != DiscoveryFragment.this.recommendChannelEmptyRow && position != DiscoveryFragment.this.extraDataStartRow && position != DiscoveryFragment.this.extraDataEndRow) {
                if (position != DiscoveryFragment.this.bannerRow) {
                    if (position == DiscoveryFragment.this.bannerStartRow || position == DiscoveryFragment.this.bannerEndRow) {
                        return 3;
                    }
                    return 0;
                }
                return 2;
            }
            return 1;
        }
    }
}
