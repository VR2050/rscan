package im.uwrkaxlmjj.ui.wallet;

import android.content.Context;
import android.content.DialogInterface;
import android.os.Bundle;
import android.text.TextUtils;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import com.blankj.utilcode.util.ColorUtils;
import com.blankj.utilcode.util.SpanUtils;
import com.litesuits.orm.db.assit.SQLBuilder;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.NotificationCenter;
import im.uwrkaxlmjj.tgnet.ConnectionsManager;
import im.uwrkaxlmjj.tgnet.RequestDelegate;
import im.uwrkaxlmjj.tgnet.TLApiModel;
import im.uwrkaxlmjj.tgnet.TLJsonResolve;
import im.uwrkaxlmjj.tgnet.TLObject;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.tgnet.TLRPCWallet;
import im.uwrkaxlmjj.ui.actionbar.ActionBar;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.components.AppTextView;
import im.uwrkaxlmjj.ui.components.RecyclerListView;
import im.uwrkaxlmjj.ui.dialogs.WalletDialog;
import im.uwrkaxlmjj.ui.load.SpinKitView;
import im.uwrkaxlmjj.ui.load.SpriteFactory;
import im.uwrkaxlmjj.ui.load.Style;
import im.uwrkaxlmjj.ui.load.sprite.Sprite;
import im.uwrkaxlmjj.ui.wallet.model.BankCardListResBean;
import im.uwrkaxlmjj.ui.wallet.model.Constants;
import im.uwrkaxlmjj.ui.wallet.model.PayChannelBean;
import im.uwrkaxlmjj.ui.wallet.utils.ExceptionUtils;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class WalletBankCardsActivity extends BaseFragment implements NotificationCenter.NotificationCenterDelegate {
    private ListAdapter adapter;
    private BankCardListResBean bankBean;
    private AppTextView btn;
    private PayChannelBean channelBean;
    private BankCardDelegate delegate;
    private ImageView ivTip;
    private RecyclerListView listView;
    private SpinKitView loadView;
    private ArrayList<BankCardListResBean> modelList;
    private int status = 0;
    private LinearLayout tipLayout;
    private TextView tvDesc;
    private TextView tvTips;

    public interface BankCardDelegate {
        void onSelected(BankCardListResBean bankCardListResBean);
    }

    public void setDelegate(BankCardDelegate delegate) {
        this.delegate = delegate;
    }

    public void setBean(PayChannelBean bean) {
        this.channelBean = bean;
    }

    public void setBankBean(BankCardListResBean bean) {
        this.bankBean = bean;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public boolean onFragmentCreate() {
        super.onFragmentCreate();
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.bandCardNeedReload);
        return super.onFragmentCreate();
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onFragmentDestroy() {
        super.onFragmentDestroy();
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.bandCardNeedReload);
        ConnectionsManager.getInstance(this.currentAccount).cancelRequestsForGuid(this.classGuid);
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public View createView(Context context) {
        this.fragmentView = LayoutInflater.from(context).inflate(R.layout.activity_wallet_banks_layout, (ViewGroup) null);
        initActionBar();
        initViews();
        showLoading();
        this.fragmentView.postDelayed(new Runnable() { // from class: im.uwrkaxlmjj.ui.wallet.WalletBankCardsActivity.1
            @Override // java.lang.Runnable
            public void run() {
                WalletBankCardsActivity.this.loadBankList();
            }
        }, 1000L);
        return this.fragmentView;
    }

    private void initActionBar() {
        this.actionBar.setTitle(LocaleController.getString(R.string.BankCard));
        this.actionBar.setBackButtonImage(R.id.ic_back);
        this.actionBar.setCastShadows(false);
        this.actionBar.setActionBarMenuOnItemClick(new ActionBar.ActionBarMenuOnItemClick() { // from class: im.uwrkaxlmjj.ui.wallet.WalletBankCardsActivity.2
            @Override // im.uwrkaxlmjj.ui.actionbar.ActionBar.ActionBarMenuOnItemClick
            public void onItemClick(int id) {
                if (id == -1) {
                    if (WalletBankCardsActivity.this.delegate != null) {
                        if (WalletBankCardsActivity.this.bankBean != null) {
                            WalletBankCardsActivity.this.delegate.onSelected(WalletBankCardsActivity.this.bankBean);
                        } else if (WalletBankCardsActivity.this.modelList != null && !WalletBankCardsActivity.this.modelList.isEmpty()) {
                            WalletBankCardsActivity.this.delegate.onSelected((BankCardListResBean) WalletBankCardsActivity.this.modelList.get(0));
                        }
                    }
                    WalletBankCardsActivity.this.finishFragment();
                }
            }
        });
    }

    private void initViews() {
        this.loadView = (SpinKitView) this.fragmentView.findViewById(R.attr.loadView);
        this.tipLayout = (LinearLayout) this.fragmentView.findViewById(R.attr.tipLayout);
        this.ivTip = (ImageView) this.fragmentView.findViewById(R.attr.ivTip);
        this.tvTips = (TextView) this.fragmentView.findViewById(R.attr.tvTips);
        this.tvDesc = (TextView) this.fragmentView.findViewById(R.attr.tvDesc);
        this.btn = (AppTextView) this.fragmentView.findViewById(R.attr.btn);
        this.listView = (RecyclerListView) this.fragmentView.findViewById(R.attr.listView);
        this.loadView.setColor(Theme.value_WalletPageBlueTextColor);
        Sprite drawable = SpriteFactory.create(Style.CIRCLE);
        this.loadView.setIndeterminateDrawable(drawable);
        LinearLayoutManager layoutManager = new LinearLayoutManager(getParentActivity());
        this.adapter = new ListAdapter(getParentActivity());
        this.listView.setEmptyView(this.tipLayout);
        this.listView.setLayoutManager(layoutManager);
        this.listView.setAdapter(this.adapter);
        this.btn.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.wallet.WalletBankCardsActivity.3
            @Override // android.view.View.OnClickListener
            public void onClick(View view) {
                if (WalletBankCardsActivity.this.status == 1) {
                    WalletBankCardsActivity.this.showLoading();
                    WalletBankCardsActivity.this.loadBankList();
                    return;
                }
                Bundle args = new Bundle();
                args.putString("supportId", WalletBankCardsActivity.this.channelBean.getPayType().getSupportId() + "");
                args.putString("templateId", WalletBankCardsActivity.this.channelBean.getPayType().getTemplateId() + "");
                WalletWithdrawAddNewAccountActivity aa = new WalletWithdrawAddNewAccountActivity(args);
                WalletBankCardsActivity.this.presentFragment(aa);
            }
        });
        this.listView.setOnItemClickListener(new RecyclerListView.OnItemClickListener() { // from class: im.uwrkaxlmjj.ui.wallet.WalletBankCardsActivity.4
            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.OnItemClickListener
            public void onItemClick(View view, int position) {
                if (position != WalletBankCardsActivity.this.modelList.size()) {
                    if (WalletBankCardsActivity.this.delegate != null) {
                        WalletBankCardsActivity.this.delegate.onSelected((BankCardListResBean) WalletBankCardsActivity.this.modelList.get(position));
                        WalletBankCardsActivity.this.finishFragment();
                        return;
                    }
                    return;
                }
                Bundle args = new Bundle();
                args.putString("supportId", WalletBankCardsActivity.this.channelBean.getPayType().getSupportId() + "");
                args.putString("templateId", WalletBankCardsActivity.this.channelBean.getPayType().getTemplateId() + "");
                WalletWithdrawAddNewAccountActivity aa = new WalletWithdrawAddNewAccountActivity(args);
                WalletBankCardsActivity.this.presentFragment(aa);
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void showLoading() {
        this.tipLayout.setVisibility(0);
        this.tvDesc.setVisibility(8);
        this.ivTip.setVisibility(8);
        this.btn.setVisibility(8);
        this.tvTips.setText(LocaleController.getString(R.string.NowLoading));
        this.tvTips.setTextColor(ColorUtils.getColor(R.color.text_descriptive_color));
        this.loadView.setVisibility(0);
    }

    private void showEmpty() {
        this.tipLayout.setVisibility(0);
        this.tvDesc.setVisibility(0);
        this.ivTip.setVisibility(0);
        this.ivTip.setImageResource(R.id.ic_add_bank_card2);
        this.btn.setVisibility(0);
        this.btn.setText(LocaleController.getString(R.string.ToBindBankCardCaps));
        this.tvTips.setText(LocaleController.getString(R.string.NoBankCard));
        this.tvTips.setTextColor(ColorUtils.getColor(R.color.text_primary_color));
        this.tvDesc.setText(LocaleController.getString(R.string.NoBanCardBind));
        this.loadView.setVisibility(8);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void showError() {
        this.tipLayout.setVisibility(0);
        this.tvDesc.setVisibility(0);
        this.ivTip.setVisibility(0);
        this.ivTip.setImageResource(R.id.ic_data_ex);
        this.btn.setVisibility(0);
        this.tvTips.setText(LocaleController.getString(R.string.SystemIsBusyAndTryAgainLater));
        this.tvTips.setTextColor(ColorUtils.getColor(R.color.text_primary_color));
        this.tvDesc.setText(LocaleController.getString(R.string.ClickTheButtonToTryAgain));
        this.btn.setText(LocaleController.getString(R.string.Refresh));
        this.loadView.setVisibility(8);
    }

    private void showContainer() {
        this.tipLayout.setVisibility(8);
        this.listView.setVisibility(0);
    }

    private void sortList() {
        ArrayList<BankCardListResBean> arrayList = this.modelList;
        if (arrayList == null) {
            return;
        }
        Collections.sort(arrayList, new Comparator<BankCardListResBean>() { // from class: im.uwrkaxlmjj.ui.wallet.WalletBankCardsActivity.5
            @Override // java.util.Comparator
            public int compare(BankCardListResBean o1, BankCardListResBean o2) {
                if (o1.getId() > o2.getId()) {
                    return -1;
                }
                if (o1.getId() < o2.getId()) {
                    return 1;
                }
                return 0;
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void loadBankList() {
        TLRPCWallet.Builder builder = new TLRPCWallet.Builder();
        builder.setBusinessKey(Constants.KEY_BANK_CARD_LIST);
        builder.addParam("userId", Integer.valueOf(getUserConfig().clientUserId));
        builder.addParam("supportId", Integer.valueOf(this.channelBean.getPayType().getSupportId()));
        TLRPCWallet.TL_paymentTrans req = builder.build();
        getConnectionsManager().bindRequestToGuid(getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.wallet.-$$Lambda$WalletBankCardsActivity$2U3KkN7I444qsKEHi3mCOjQCnSg
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$loadBankList$1$WalletBankCardsActivity(tLObject, tL_error);
            }
        }), this.classGuid);
    }

    public /* synthetic */ void lambda$loadBankList$1$WalletBankCardsActivity(TLObject response, TLRPC.TL_error error) {
        if (error != null) {
            ExceptionUtils.handlePayChannelException(error.text);
            return;
        }
        if (response instanceof TLRPCWallet.TL_paymentTransResult) {
            TLRPCWallet.TL_paymentTransResult result = (TLRPCWallet.TL_paymentTransResult) response;
            TLApiModel<BankCardListResBean> parse = TLJsonResolve.parse3(result.data, BankCardListResBean.class);
            if (parse.isSuccess()) {
                this.status = 0;
                this.modelList = (ArrayList) parse.modelList;
                sortList();
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.wallet.-$$Lambda$WalletBankCardsActivity$kJIXippPVhKxS-jjar_SYJg_2ok
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$null$0$WalletBankCardsActivity();
                    }
                });
                return;
            }
            this.status = 1;
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.wallet.WalletBankCardsActivity.6
                @Override // java.lang.Runnable
                public void run() {
                    WalletBankCardsActivity.this.showError();
                    if (WalletBankCardsActivity.this.adapter != null) {
                        WalletBankCardsActivity.this.adapter.notifyDataSetChanged();
                    }
                }
            });
        }
    }

    public /* synthetic */ void lambda$null$0$WalletBankCardsActivity() {
        showEmpty();
        ListAdapter listAdapter = this.adapter;
        if (listAdapter != null) {
            listAdapter.notifyDataSetChanged();
        }
    }

    @Override // im.uwrkaxlmjj.messenger.NotificationCenter.NotificationCenterDelegate
    public void didReceivedNotification(int id, int account, Object... args) {
        if (id == NotificationCenter.bandCardNeedReload) {
            showLoading();
            loadBankList();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    class ListAdapter extends RecyclerListView.SelectionAdapter {
        private Context mContext;

        public ListAdapter(Context context) {
            this.mContext = context;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemViewType(int position) {
            if (position == WalletBankCardsActivity.this.modelList.size()) {
                return 1;
            }
            return 0;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public RecyclerView.ViewHolder onCreateViewHolder(ViewGroup parent, int viewType) {
            View view = viewType != 1 ? LayoutInflater.from(this.mContext).inflate(R.layout.item_bank_card_layout, parent, false) : LayoutInflater.from(this.mContext).inflate(R.layout.item_button_layout, parent, false);
            return new RecyclerListView.Holder(view);
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void onBindViewHolder(RecyclerView.ViewHolder holder, int position) {
            String shortNum;
            int type = holder.getItemViewType();
            if (type != 1) {
                View container = holder.itemView.findViewById(R.attr.container);
                TextView tvSelected = (TextView) holder.itemView.findViewById(R.attr.tvSelected);
                TextView tvName = (TextView) holder.itemView.findViewById(R.attr.tvName);
                TextView tvNumber = (TextView) holder.itemView.findViewById(R.attr.tvNumber);
                ImageView ivEdit = (ImageView) holder.itemView.findViewById(R.attr.ivEdit);
                if (position == 0) {
                    container.setBackgroundResource(R.drawable.cell_top_selector);
                } else {
                    container.setBackgroundResource(R.drawable.cell_middle_selector);
                }
                ivEdit.setTag(Integer.valueOf(position));
                tvSelected.setBackground(Theme.createRoundRectDrawable(AndroidUtilities.dp(4.0f), ColorUtils.getColor(R.color.text_blue_color)));
                BankCardListResBean bean = (BankCardListResBean) WalletBankCardsActivity.this.modelList.get(position);
                if (WalletBankCardsActivity.this.bankBean != null) {
                    tvSelected.setVisibility(WalletBankCardsActivity.this.bankBean.getId() != bean.getId() ? 8 : 0);
                } else {
                    tvSelected.setVisibility(position != 0 ? 8 : 0);
                }
                if (bean != null && !TextUtils.isEmpty(bean.getInfo())) {
                    String cardNum = bean.getCardNumber() + "";
                    if (cardNum.length() > 4) {
                        shortNum = cardNum.substring(cardNum.length() - 4);
                    } else {
                        shortNum = cardNum;
                    }
                    String name = "";
                    String reactType = bean.getReactType();
                    if (reactType != null) {
                        name = reactType;
                    }
                    if (TextUtils.isEmpty(name)) {
                        name = WalletBankCardsActivity.this.channelBean.getPayType().getName();
                    }
                    SpanUtils.with(tvName).append(name).append(SQLBuilder.PARENTHESES_LEFT).append(shortNum).append(SQLBuilder.PARENTHESES_RIGHT).create();
                    tvNumber.setText(cardNum);
                }
                ivEdit.setBackground(Theme.createSelectorDrawable(ColorUtils.getColor(R.color.click_selector)));
                ivEdit.setOnClickListener(new AnonymousClass1());
                return;
            }
            LinearLayout container2 = (LinearLayout) holder.itemView.findViewById(R.attr.container);
            TextView tvAction = (TextView) holder.itemView.findViewById(R.attr.tvAction);
            tvAction.setText(LocaleController.getString(R.string.AddNewBankCard));
            container2.setBackgroundResource(R.drawable.cell_bottom_selector);
        }

        /* JADX INFO: renamed from: im.uwrkaxlmjj.ui.wallet.WalletBankCardsActivity$ListAdapter$1, reason: invalid class name */
        class AnonymousClass1 implements View.OnClickListener {
            AnonymousClass1() {
            }

            @Override // android.view.View.OnClickListener
            public void onClick(View view) {
                int pos = ((Integer) view.getTag()).intValue();
                WalletDialog dialog = new WalletDialog(WalletBankCardsActivity.this.getParentActivity());
                dialog.setMessage(LocaleController.getString(R.string.AreYouSureDeleteBankCard), 16, true, true, false);
                dialog.setNegativeButton(LocaleController.getString("Cancel", R.string.Cancel), null);
                dialog.setPositiveButton(LocaleController.getString("Confirm", R.string.Confirm), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.wallet.-$$Lambda$WalletBankCardsActivity$ListAdapter$1$qgqzNiyrZimz4-VzhBl0pHLFUCI
                    @Override // android.content.DialogInterface.OnClickListener
                    public final void onClick(DialogInterface dialogInterface, int i) {
                        this.f$0.lambda$onClick$0$WalletBankCardsActivity$ListAdapter$1(dialogInterface, i);
                    }
                });
                dialog.getPositiveButton().setTextColor(ColorUtils.getColor(R.color.text_red_color));
                dialog.getNegativeButton().setTextColor(ColorUtils.getColor(R.color.text_secondary_color));
                WalletBankCardsActivity.this.showDialog(dialog);
            }

            public /* synthetic */ void lambda$onClick$0$WalletBankCardsActivity$ListAdapter$1(DialogInterface dialogInterface, int i) {
                WalletBankCardsActivity.this.finishFragment();
            }
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemCount() {
            if (WalletBankCardsActivity.this.modelList == null || WalletBankCardsActivity.this.modelList.size() == 0) {
                return 0;
            }
            return WalletBankCardsActivity.this.modelList.size() + 1;
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SelectionAdapter
        public boolean isEnabled(RecyclerView.ViewHolder holder) {
            return false;
        }
    }
}
