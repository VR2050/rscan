package im.uwrkaxlmjj.ui.hui.cdnvip;

import android.content.Context;
import android.content.DialogInterface;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import com.blankj.utilcode.util.GsonUtils;
import com.litesuits.orm.db.assit.SQLBuilder;
import im.uwrkaxlmjj.javaBean.cdnVip.CdnVipDetailsListBean;
import im.uwrkaxlmjj.javaBean.cdnVip.CdnVipInfoBean;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.tgnet.RequestDelegate;
import im.uwrkaxlmjj.tgnet.TLObject;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.tgnet.TLRPCCdn;
import im.uwrkaxlmjj.ui.actionbar.ActionBar;
import im.uwrkaxlmjj.ui.actionbar.AlertDialog;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.components.LayoutHelper;
import im.uwrkaxlmjj.ui.components.RecyclerListView;
import im.uwrkaxlmjj.ui.components.toast.ToastUtils;
import im.uwrkaxlmjj.ui.hui.adapter.pageAdapter.PageHolder;
import im.uwrkaxlmjj.ui.hui.wallet_public.utils.WalletDialogUtil;
import im.uwrkaxlmjj.ui.hui.wallet_public.utils.WalletErrorUtil;
import im.uwrkaxlmjj.ui.hviews.MryEmptyView;
import im.uwrkaxlmjj.ui.hviews.MryLinearLayout;
import im.uwrkaxlmjj.ui.hviews.MryRoundButton;
import im.uwrkaxlmjj.ui.hviews.MryTextView;
import java.util.List;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class CdnVipDetailsActivity extends BaseFragment {
    private Adapter adapter;
    private CdnVipInfoBean cdnVipInfoBean;
    private List<CdnVipDetailsListBean.Item> data;
    private Delegate delegate;
    private MryEmptyView emptyView;
    private RecyclerListView rv;

    public interface Delegate {
        void onResult(CdnVipInfoBean cdnVipInfoBean);
    }

    public CdnVipDetailsActivity(CdnVipInfoBean cdnVipInfoBean) {
        this.cdnVipInfoBean = cdnVipInfoBean;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public boolean onFragmentCreate() {
        return this.cdnVipInfoBean != null;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public View createView(Context context) {
        this.actionBar = createActionBar(context);
        this.actionBar.setTitle(LocaleController.getString(R.string.MemberDetails));
        this.actionBar.setBackButtonImage(R.id.ic_back);
        this.actionBar.setCastShadows(false);
        this.actionBar.setActionBarMenuOnItemClick(new ActionBar.ActionBarMenuOnItemClick() { // from class: im.uwrkaxlmjj.ui.hui.cdnvip.CdnVipDetailsActivity.1
            @Override // im.uwrkaxlmjj.ui.actionbar.ActionBar.ActionBarMenuOnItemClick
            public void onItemClick(int id) {
                if (id == -1) {
                    CdnVipDetailsActivity.this.finishFragment();
                }
            }
        });
        this.actionBar.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundGray));
        FrameLayout container = new FrameLayout(context);
        container.setLayoutParams(new FrameLayout.LayoutParams(-1, -1));
        this.fragmentView = container;
        this.fragmentView.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundGray));
        MryEmptyView mryEmptyView = new MryEmptyView(context);
        this.emptyView = mryEmptyView;
        mryEmptyView.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundGray));
        this.emptyView.attach(container);
        this.emptyView.setEmptyResId(R.id.img_empty_default);
        this.emptyView.setEmptyText(LocaleController.getString(R.string.YouDonottHaveRecordYet));
        this.emptyView.showLoading();
        RecyclerListView recyclerListView = new RecyclerListView(context);
        this.rv = recyclerListView;
        container.addView(recyclerListView, LayoutHelper.createFrame(-1, -1.0f));
        this.rv.setLayoutManager(new LinearLayoutManager(context));
        Adapter adapter = new Adapter();
        this.adapter = adapter;
        this.rv.setAdapter(adapter);
        this.fragmentView.postDelayed(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.cdnvip.-$$Lambda$CdnVipDetailsActivity$LSYecBS_tp8F3nz7PcMADm0uC_U
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.getData();
            }
        }, 300L);
        return this.fragmentView;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void getData() {
        TLRPCCdn.TL_getUserCdnVipPayRecords req = new TLRPCCdn.TL_getUserCdnVipPayRecords();
        getConnectionsManager().bindRequestToGuid(getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.hui.cdnvip.-$$Lambda$CdnVipDetailsActivity$geSMsYBiSbSjGC8VB4w1WRE7hd4
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$getData$1$CdnVipDetailsActivity(tLObject, tL_error);
            }
        }), this.classGuid);
    }

    public /* synthetic */ void lambda$getData$1$CdnVipDetailsActivity(final TLObject response, final TLRPC.TL_error error) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.cdnvip.-$$Lambda$CdnVipDetailsActivity$FB9xG-nJDPaiCxRNwvCvZqP6zpU
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$0$CdnVipDetailsActivity(error, response);
            }
        });
    }

    public /* synthetic */ void lambda$null$0$CdnVipDetailsActivity(TLRPC.TL_error error, TLObject response) {
        if (error != null) {
            parseError(error.code, error.text);
            return;
        }
        if (response instanceof TLRPCCdn.TL_userCdnPayList) {
            try {
                CdnVipDetailsListBean bean = (CdnVipDetailsListBean) GsonUtils.getGson().fromJson(((TLRPCCdn.TL_userCdnPayList) response).pay_list.data, CdnVipDetailsListBean.class);
                if (bean != null) {
                    this.data = bean.getInfoList();
                }
                if (this.adapter != null) {
                    this.adapter.notifyDataSetChanged();
                }
                if (this.emptyView != null) {
                    if (this.data != null && !this.data.isEmpty()) {
                        this.emptyView.showContent();
                        return;
                    }
                    this.emptyView.showEmpty();
                }
            } catch (Exception e) {
                parseError(0, e.getMessage());
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void openOrCloseAutoPay() {
        if (this.cdnVipInfoBean == null) {
            return;
        }
        TLRPCCdn.TL_setCdnVipAutoPay req = new TLRPCCdn.TL_setCdnVipAutoPay();
        final boolean isOpenAutoPay = this.cdnVipInfoBean.isAutoPay();
        req.is_open = !isOpenAutoPay;
        final AlertDialog progressDialog = new AlertDialog(getParentActivity(), 3);
        progressDialog.setOnCancelListener(new DialogInterface.OnCancelListener() { // from class: im.uwrkaxlmjj.ui.hui.cdnvip.-$$Lambda$CdnVipDetailsActivity$qBPyVPi_GzGbsAF3V9W2coftSHc
            @Override // android.content.DialogInterface.OnCancelListener
            public final void onCancel(DialogInterface dialogInterface) {
                this.f$0.lambda$openOrCloseAutoPay$2$CdnVipDetailsActivity(dialogInterface);
            }
        });
        progressDialog.show();
        getConnectionsManager().bindRequestToGuid(getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.hui.cdnvip.-$$Lambda$CdnVipDetailsActivity$AQtINkpBYZJVMyhaSbaYCSb6k0E
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$openOrCloseAutoPay$4$CdnVipDetailsActivity(progressDialog, isOpenAutoPay, tLObject, tL_error);
            }
        }), this.classGuid);
    }

    public /* synthetic */ void lambda$openOrCloseAutoPay$2$CdnVipDetailsActivity(DialogInterface dialog) {
        getConnectionsManager().cancelRequestsForGuid(this.classGuid);
    }

    public /* synthetic */ void lambda$openOrCloseAutoPay$4$CdnVipDetailsActivity(final AlertDialog progressDialog, final boolean isOpenAutoPay, final TLObject response, final TLRPC.TL_error error) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.cdnvip.-$$Lambda$CdnVipDetailsActivity$dBLQHYLbqomiQJlOyFdPFl8LafI
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$3$CdnVipDetailsActivity(progressDialog, error, response, isOpenAutoPay);
            }
        });
    }

    public /* synthetic */ void lambda$null$3$CdnVipDetailsActivity(AlertDialog progressDialog, TLRPC.TL_error error, TLObject response, boolean isOpenAutoPay) {
        if (progressDialog != null) {
            progressDialog.dismiss();
        }
        if (error != null) {
            parseError(1, error.text);
            return;
        }
        if (response instanceof TLRPCCdn.TL_userCdnVipInfo) {
            try {
                ToastUtils.show((CharSequence) LocaleController.getString(isOpenAutoPay ? R.string.CdnVipAutomaticCloseSuccess : R.string.CdnVipAutomaticOpenSuccess));
                CdnVipInfoBean cdnVipInfoBean = (CdnVipInfoBean) GsonUtils.fromJson(((TLRPCCdn.TL_userCdnVipInfo) response).vip_info.data, CdnVipInfoBean.class);
                this.cdnVipInfoBean = cdnVipInfoBean;
                if (this.adapter != null) {
                    this.adapter.notifyDataSetChanged();
                }
                if (this.delegate != null) {
                    this.delegate.onResult(cdnVipInfoBean);
                }
            } catch (Exception e) {
                parseError(1, e.getMessage());
            }
        }
    }

    private void parseError(int errorCode, String errorMsg) {
        if (errorCode == 1) {
            WalletDialogUtil.showConfirmBtnWalletDialog(this, LocaleController.getString(this.cdnVipInfoBean.isAutoPay() ? R.string.CdnVipAutomaticCloseFailed : R.string.CdnVipAutomaticOpenFailed));
        } else {
            WalletDialogUtil.showConfirmBtnWalletDialog(this, WalletErrorUtil.getErrorDescription(errorMsg));
        }
    }

    public CdnVipDetailsActivity setDelegate(Delegate delegate) {
        this.delegate = delegate;
        return this;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onFragmentDestroy() {
        super.onFragmentDestroy();
        this.adapter = null;
    }

    /* JADX INFO: Access modifiers changed from: private */
    class Adapter extends RecyclerListView.SelectionAdapter {
        private Adapter() {
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SelectionAdapter
        public boolean isEnabled(RecyclerView.ViewHolder holder) {
            return false;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public PageHolder onCreateViewHolder(ViewGroup parent, int viewType) {
            if (viewType == 0) {
                return new PageHolder(LayoutInflater.from(CdnVipDetailsActivity.this.getParentActivity()).inflate(R.layout.item_cdn_vip_details, parent, false));
            }
            MryTextView tv = new MryTextView(CdnVipDetailsActivity.this.getParentActivity());
            tv.setTextSize(13.0f);
            tv.setGravity(17);
            tv.setLayoutParams(new RecyclerView.LayoutParams(-1, AndroidUtilities.dp(60.0f)));
            tv.setText(LocaleController.getString(R.string.friends_circle_location_search_nomore_hint) + "~");
            tv.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteGrayText3));
            return new PageHolder(tv, 0);
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void onBindViewHolder(RecyclerView.ViewHolder holder1, int position) {
            if (holder1.getItemViewType() != 0 || CdnVipDetailsActivity.this.cdnVipInfoBean == null) {
                return;
            }
            PageHolder holder = (PageHolder) holder1;
            MryLinearLayout root = (MryLinearLayout) holder.itemView;
            root.setRadius(AndroidUtilities.dp(10.0f));
            MryRoundButton btn = (MryRoundButton) holder.getView(R.attr.btn);
            btn.setTextColor(-1);
            CdnVipDetailsListBean.Item item = (CdnVipDetailsListBean.Item) CdnVipDetailsActivity.this.data.get(position);
            if (CdnVipDetailsActivity.this.cdnVipInfoBean.cdnVipIsAvailable()) {
                if (position == 0) {
                    holder.setText(R.attr.tvStatus, LocaleController.getString(R.string.AppVip));
                    if (CdnVipDetailsActivity.this.cdnVipInfoBean.isAutoPay()) {
                        btn.setText(LocaleController.getString(R.string.TurnOffAutomaticRenewal));
                        btn.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlueButton));
                        btn.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.cdnvip.-$$Lambda$CdnVipDetailsActivity$Adapter$wq-1MUdhOXF_nYQxFnFSKTYNHqc
                            @Override // android.view.View.OnClickListener
                            public final void onClick(View view) {
                                this.f$0.lambda$onBindViewHolder$1$CdnVipDetailsActivity$Adapter(view);
                            }
                        });
                        holder.setGone((View) btn, false);
                        holder.setGone(R.attr.tvMoney, true);
                        holder.setText(R.attr.tvExprieTime, item.getBgnTimeFormat() + LocaleController.getString(R.string.SoFar));
                        return;
                    }
                } else {
                    holder.setText(R.attr.tvStatus, LocaleController.getString(R.string.AppVip) + SQLBuilder.PARENTHESES_LEFT + LocaleController.getString(R.string.RequestExpired) + SQLBuilder.PARENTHESES_RIGHT);
                }
            } else {
                holder.setText(R.attr.tvStatus, LocaleController.getString(R.string.AppVip) + SQLBuilder.PARENTHESES_LEFT + LocaleController.getString(R.string.RequestExpired) + SQLBuilder.PARENTHESES_RIGHT);
            }
            btn.setOnClickListener(null);
            holder.setGone((View) btn, true);
            holder.setGone(R.attr.tvMoney, false);
            holder.setText(R.attr.tvMoney, item.getMoney());
            holder.setText(R.attr.tvExprieTime, item.getBgnTimeFormat() + "-" + item.getEndTimeFormat());
        }

        public /* synthetic */ void lambda$onBindViewHolder$1$CdnVipDetailsActivity$Adapter(View v) {
            WalletDialogUtil.showWalletDialog(CdnVipDetailsActivity.this, "", LocaleController.getString(R.string.CdnVipConfirmToCloseAutomicRenewal), LocaleController.getString(R.string.Cancel), LocaleController.getString(R.string.OK), null, new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.cdnvip.-$$Lambda$CdnVipDetailsActivity$Adapter$B8AbFxjdbQPTyGWmDr6BBUJwQio
                @Override // android.content.DialogInterface.OnClickListener
                public final void onClick(DialogInterface dialogInterface, int i) {
                    this.f$0.lambda$null$0$CdnVipDetailsActivity$Adapter(dialogInterface, i);
                }
            }, null);
        }

        public /* synthetic */ void lambda$null$0$CdnVipDetailsActivity$Adapter(DialogInterface dialog, int which) {
            CdnVipDetailsActivity.this.openOrCloseAutoPay();
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemViewType(int position) {
            return position == getItemCount() - 1 ? 1 : 0;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemCount() {
            if (CdnVipDetailsActivity.this.data == null) {
                return 0;
            }
            return CdnVipDetailsActivity.this.data.size() + 1;
        }
    }
}
