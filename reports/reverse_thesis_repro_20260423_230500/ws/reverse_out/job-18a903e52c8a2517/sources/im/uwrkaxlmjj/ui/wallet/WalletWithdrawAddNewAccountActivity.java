package im.uwrkaxlmjj.ui.wallet;

import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.text.Editable;
import android.text.TextUtils;
import android.text.TextWatcher;
import android.util.SparseArray;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.core.content.FileProvider;
import androidx.exifinterface.media.ExifInterface;
import androidx.recyclerview.widget.GridLayoutManager;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import com.bjz.comm.net.bean.HuanHuiUploadFileResponseBean;
import com.bjz.comm.net.factory.ApiHuanHuiFactory;
import com.blankj.utilcode.util.ColorUtils;
import com.blankj.utilcode.util.GsonUtils;
import com.google.android.exoplayer2.text.ttml.TtmlNode;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.FileLog;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.MediaController;
import im.uwrkaxlmjj.messenger.NotificationCenter;
import im.uwrkaxlmjj.messenger.SendMessagesHelper;
import im.uwrkaxlmjj.messenger.VideoEditedInfo;
import im.uwrkaxlmjj.tgnet.RequestDelegate;
import im.uwrkaxlmjj.tgnet.TLApiModel;
import im.uwrkaxlmjj.tgnet.TLApiModel2;
import im.uwrkaxlmjj.tgnet.TLJsonResolve;
import im.uwrkaxlmjj.tgnet.TLObject;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.tgnet.TLRPCWallet;
import im.uwrkaxlmjj.ui.PhotoAlbumPickerActivity;
import im.uwrkaxlmjj.ui.PhotoPickerActivity;
import im.uwrkaxlmjj.ui.PhotoViewer;
import im.uwrkaxlmjj.ui.actionbar.ActionBar;
import im.uwrkaxlmjj.ui.actionbar.ActionBarMenu;
import im.uwrkaxlmjj.ui.actionbar.ActionBarMenuItem;
import im.uwrkaxlmjj.ui.actionbar.AlertDialog;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.components.LayoutHelper;
import im.uwrkaxlmjj.ui.components.RecyclerListView;
import im.uwrkaxlmjj.ui.components.recyclerview.OnItemClickListener;
import im.uwrkaxlmjj.ui.components.toast.ToastUtils;
import im.uwrkaxlmjj.ui.dialogs.BottomDialog;
import im.uwrkaxlmjj.ui.dialogs.WalletSelect1LineDialog;
import im.uwrkaxlmjj.ui.hui.adapter.pageAdapter.PageHolder;
import im.uwrkaxlmjj.ui.hui.decoration.DefaultItemDecoration;
import im.uwrkaxlmjj.ui.hui.visualcall.PermissionUtils;
import im.uwrkaxlmjj.ui.hui.wallet_public.utils.WalletErrorUtil;
import im.uwrkaxlmjj.ui.hviews.MryEditText;
import im.uwrkaxlmjj.ui.hviews.MryEmptyView;
import im.uwrkaxlmjj.ui.hviews.MryFrameLayout;
import im.uwrkaxlmjj.ui.hviews.MryTextView;
import im.uwrkaxlmjj.ui.utils.number.NumberUtil;
import im.uwrkaxlmjj.ui.wallet.model.Constants;
import im.uwrkaxlmjj.ui.wallet.model.WalletPaymentBankCardBean;
import im.uwrkaxlmjj.ui.wallet.model.WalletWithdrawTemplateBean;
import im.uwrkaxlmjj.ui.wallet.utils.ExceptionUtils;
import im.uwrkaxlmjj.ui.wallet.utils.GlideUtil;
import io.reactivex.Observable;
import io.reactivex.android.schedulers.AndroidSchedulers;
import io.reactivex.disposables.Disposable;
import io.reactivex.functions.Consumer;
import io.reactivex.schedulers.Schedulers;
import java.io.File;
import java.io.UnsupportedEncodingException;
import java.lang.ref.WeakReference;
import java.net.FileNameMap;
import java.net.URLConnection;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.List;
import mpEIGo.juqQQs.esbSDO.R;
import okhttp3.MediaType;
import okhttp3.MultipartBody;
import okhttp3.RequestBody;
import org.webrtc.mozi.JavaScreenCapturer;

/* JADX INFO: loaded from: classes5.dex */
public class WalletWithdrawAddNewAccountActivity extends BaseFragment {
    private static final String TAG = "WalletWithdrawAddNewAccountActivity";
    public static final int TYPE_WITHDRAW_ADD_NEW = 0;
    public static final int TYPE_WITHDRAW_MODIFY = 1;
    private Adapter adapter;
    private String currentPicturePath;
    private ActionBarMenuItem doneMenu;
    private MryEmptyView emptyView;
    private boolean isBinding;
    private boolean isSelectPicture;
    private WalletPaymentBankCardBean paymentBankCardBean;
    private RecyclerListView rv;
    private int selectChildPosition;
    private int selectGroupPosition;
    private String supportId;
    private List<WalletWithdrawTemplateBean> templateData;
    private String templateId;
    private Disposable uploadPictureDiaposable;

    public void setPaymentBankCardBean(WalletPaymentBankCardBean paymentBankCardBean) {
        this.paymentBankCardBean = paymentBankCardBean;
    }

    public WalletWithdrawAddNewAccountActivity() {
        this.selectGroupPosition = -1;
        this.selectChildPosition = -1;
    }

    public WalletWithdrawAddNewAccountActivity(Bundle args) {
        super(args);
        this.selectGroupPosition = -1;
        this.selectChildPosition = -1;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public boolean onFragmentCreate() {
        if (getArguments() == null) {
            return false;
        }
        this.supportId = getArguments().getString("supportId", null);
        String string = getArguments().getString("templateId", null);
        this.templateId = string;
        String str = this.supportId;
        if (str == null || string == null || !NumberUtil.isNumber(str) || !NumberUtil.isNumber(this.templateId)) {
            return false;
        }
        return super.onFragmentCreate();
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public View createView(Context context) {
        FrameLayout frameLayout = new FrameLayout(context);
        ScrollView container = new ScrollView(context);
        frameLayout.addView(container, LayoutHelper.createFrame(-1, -1.0f));
        this.fragmentView = frameLayout;
        this.fragmentView.setBackgroundResource(R.color.window_background_gray);
        container.setFillViewport(true);
        initActionBar();
        initView(context);
        return this.fragmentView;
    }

    private void initActionBar() {
        this.actionBar.setCastShadows(false);
        this.actionBar.setBackButtonImage(R.id.ic_back);
        this.actionBar.setTitle(LocaleController.getString(R.string.AddBankCardTitle));
        ActionBarMenu menu = this.actionBar.createMenu();
        ActionBarMenuItem actionBarMenuItemAddItem = menu.addItem(1, LocaleController.getString(R.string.Done));
        this.doneMenu = actionBarMenuItemAddItem;
        ((TextView) actionBarMenuItemAddItem.getContentView()).setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteGrayText3));
        this.actionBar.setActionBarMenuOnItemClick(new ActionBar.ActionBarMenuOnItemClick() { // from class: im.uwrkaxlmjj.ui.wallet.WalletWithdrawAddNewAccountActivity.1
            @Override // im.uwrkaxlmjj.ui.actionbar.ActionBar.ActionBarMenuOnItemClick
            public void onItemClick(int id) {
                super.onItemClick(id);
                if (id != -1) {
                    if (WalletWithdrawAddNewAccountActivity.this.check(true)) {
                        WalletWithdrawAddNewAccountActivity.this.startToUploadPictrues();
                        return;
                    }
                    return;
                }
                WalletWithdrawAddNewAccountActivity.this.finishFragment();
            }
        });
    }

    private void initView(Context context) {
        MryEmptyView mryEmptyView = new MryEmptyView(context);
        this.emptyView = mryEmptyView;
        mryEmptyView.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundGray));
        this.emptyView.attach((ViewGroup) this.fragmentView);
        LinearLayout linearLayout = new LinearLayout(context);
        ((FrameLayout) this.fragmentView).addView(linearLayout, LayoutHelper.createFrame(-1, -1.0f));
        linearLayout.setOrientation(1);
        MryFrameLayout containerRv = new MryFrameLayout(context);
        linearLayout.addView(containerRv, LayoutHelper.createFrame(-1, -1.0f));
        RecyclerListView recyclerListView = new RecyclerListView(context);
        this.rv = recyclerListView;
        containerRv.addView(recyclerListView, LayoutHelper.createFrame(-1, -2, 51));
        this.rv.addItemDecoration(new DefaultItemDecoration().setDividerColor(0).setDividerHeight(AndroidUtilities.dp(12.0f)));
        this.rv.setItemAnimator(null);
        this.rv.setPadding(0, 0, 0, AndroidUtilities.dp(50.0f));
        this.rv.setClipToPadding(false);
        this.rv.setLayoutManager(new LinearLayoutManager(context));
        this.rv.setOnItemClickListener(new RecyclerListView.OnItemClickListener() { // from class: im.uwrkaxlmjj.ui.wallet.-$$Lambda$WalletWithdrawAddNewAccountActivity$c6C9KCj2Hx6nBbsg8uEXyV4h6ZY
            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.OnItemClickListener
            public final void onItemClick(View view, int i) {
                WalletWithdrawAddNewAccountActivity.lambda$initView$0(view, i);
            }
        });
        Adapter adapter = new Adapter();
        this.adapter = adapter;
        this.rv.setAdapter(adapter);
        this.emptyView.showLoading();
    }

    static /* synthetic */ void lambda$initView$0(View view, int position) {
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onResume() {
        super.onResume();
        AndroidUtilities.requestAdjustResize(getParentActivity(), this.classGuid);
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onPause() {
        super.onPause();
        AndroidUtilities.removeAdjustResize(getParentActivity(), this.classGuid);
    }

    private void getTemplateData() {
        TLRPCWallet.TL_paymentTrans req = new TLRPCWallet.Builder().setBusinessKey("get_withdraw_template").addParam("templateId", Integer.valueOf(Integer.parseInt(this.templateId))).build();
        getConnectionsManager().bindRequestToGuid(getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.wallet.-$$Lambda$WalletWithdrawAddNewAccountActivity$Js831aWfJF1CBcVEVQENWL6SFIM
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$getTemplateData$4$WalletWithdrawAddNewAccountActivity(tLObject, tL_error);
            }
        }), this.classGuid);
    }

    public /* synthetic */ void lambda$getTemplateData$4$WalletWithdrawAddNewAccountActivity(TLObject response, final TLRPC.TL_error error) {
        if (isFinishing()) {
            return;
        }
        if (error == null && (response instanceof TLRPCWallet.TL_paymentTransResult)) {
            TLRPCWallet.TL_paymentTransResult result = (TLRPCWallet.TL_paymentTransResult) response;
            final TLApiModel<WalletWithdrawTemplateBean> model = TLJsonResolve.parse(result.data, (Class<?>) WalletWithdrawTemplateBean.class);
            if (model.isSuccess()) {
                this.templateData = WalletWithdrawTemplateBean.recreateData(model.modelList, this.paymentBankCardBean);
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.wallet.-$$Lambda$WalletWithdrawAddNewAccountActivity$NkaC_BEjTd1regoCjyCmIi8LJVg
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$null$1$WalletWithdrawAddNewAccountActivity();
                    }
                });
                return;
            } else {
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.wallet.-$$Lambda$WalletWithdrawAddNewAccountActivity$jKQxFtOcqMFmGjr2ArWmnGME0I8
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$null$2$WalletWithdrawAddNewAccountActivity(model);
                    }
                });
                return;
            }
        }
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.wallet.-$$Lambda$WalletWithdrawAddNewAccountActivity$iyZ5wowzSukAAi2OQ2cuAPb2J6w
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$3$WalletWithdrawAddNewAccountActivity(error);
            }
        });
    }

    public /* synthetic */ void lambda$null$1$WalletWithdrawAddNewAccountActivity() {
        Adapter adapter = this.adapter;
        if (adapter != null) {
            adapter.notifyDataSetChanged();
        }
        MryEmptyView mryEmptyView = this.emptyView;
        if (mryEmptyView != null) {
            mryEmptyView.showContent();
        }
    }

    public /* synthetic */ void lambda$null$2$WalletWithdrawAddNewAccountActivity(TLApiModel model) {
        MryEmptyView mryEmptyView = this.emptyView;
        if (mryEmptyView != null) {
            mryEmptyView.showError(model.message);
        }
    }

    public /* synthetic */ void lambda$null$3$WalletWithdrawAddNewAccountActivity(TLRPC.TL_error error) {
        MryEmptyView mryEmptyView = this.emptyView;
        if (mryEmptyView != null) {
            mryEmptyView.showError(WalletErrorUtil.getErrorDescription(error.text));
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public boolean check(boolean showToast) {
        List<WalletWithdrawTemplateBean> list;
        if (isFinishing() || this.rv == null || this.adapter == null || (list = this.templateData) == null) {
            return false;
        }
        for (WalletWithdrawTemplateBean b : list) {
            if (b != null) {
                if (b.isTypeInputText()) {
                    if (TextUtils.isEmpty(b.getTextInput())) {
                        if (showToast) {
                            ToastUtils.show((CharSequence) b.getExplan());
                        }
                        return false;
                    }
                } else if (b.isTypeSelect()) {
                    if (b.getSelectDictItem() == null) {
                        if (showToast) {
                            ToastUtils.show((CharSequence) b.getExplan());
                        }
                        return false;
                    }
                } else if (!b.isTypePicture()) {
                    continue;
                } else {
                    if (b.getPictureArray() == null) {
                        if (showToast) {
                            ToastUtils.show((CharSequence) b.getExplan());
                        }
                        return false;
                    }
                    for (int i = 0; i < b.getPictureCount(); i++) {
                        if (!b.hasPictureDataInIndex(i, this.paymentBankCardBean == null)) {
                            if (showToast) {
                                ToastUtils.show((CharSequence) b.getExplan());
                            }
                            return false;
                        }
                    }
                }
            }
        }
        return true;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void changeNextButtonEnable() {
        if (this.doneMenu != null) {
            if (check(false)) {
                ((TextView) this.doneMenu.getContentView()).setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlueText));
            } else {
                ((TextView) this.doneMenu.getContentView()).setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteGrayText3));
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void startToUploadPictrues() {
        AlertDialog progressDialog = new AlertDialog(getParentActivity(), 3);
        progressDialog.setCanCancel(true);
        progressDialog.setOnCancelListener(new DialogInterface.OnCancelListener() { // from class: im.uwrkaxlmjj.ui.wallet.-$$Lambda$WalletWithdrawAddNewAccountActivity$YcYo4_Z8UCT1Xr6HAEpC30AiITc
            @Override // android.content.DialogInterface.OnCancelListener
            public final void onCancel(DialogInterface dialogInterface) {
                this.f$0.lambda$startToUploadPictrues$5$WalletWithdrawAddNewAccountActivity(dialogInterface);
            }
        });
        showDialog(progressDialog);
        toUploadPictures();
    }

    public /* synthetic */ void lambda$startToUploadPictrues$5$WalletWithdrawAddNewAccountActivity(DialogInterface dialog) {
        cancelUploadPicture();
        getConnectionsManager().cancelRequestsForGuid(this.classGuid);
    }

    private void toUploadPictures() {
        List<WalletWithdrawTemplateBean> list = this.templateData;
        if (list == null || list.size() == 0) {
            return;
        }
        boolean allUploaded = true;
        for (int i = 0; i < this.templateData.size(); i++) {
            WalletWithdrawTemplateBean t = this.templateData.get(i);
            if (t != null && t.isTypePicture() && t.getPictureArray() != null) {
                int j = 0;
                while (true) {
                    if (j >= t.getPictureArray().length) {
                        break;
                    }
                    WalletWithdrawTemplateBean.PictureBean pb = t.getPictureBeanIndex(j);
                    if (pb != null) {
                        if (pb.checkNeedToUploadPictureByIndex(this.paymentBankCardBean == null)) {
                            allUploaded = false;
                            toUploadPicture(i, j, pb.getPath());
                            break;
                        }
                    }
                    j++;
                }
            }
        }
        if (allUploaded) {
            addNewPaymentAccount();
        }
    }

    private void toUploadPicture(final int groupPosition, final int childPosition, String path) {
        File file = new File(path);
        if (!file.exists()) {
            return;
        }
        RequestBody fileBody = RequestBody.create(MediaType.parse(guessMimeType(file.getName())), file);
        RequestBody requestBody = new MultipartBody.Builder().setType(MultipartBody.FORM).addFormDataPart("type", "jpg").addFormDataPart("file", file.getName(), fileBody).build();
        Observable<HuanHuiUploadFileResponseBean> observable = ApiHuanHuiFactory.getInstance().getApiHuanHui().uploadFile("*/*", "gzip, deflate, br", requestBody);
        this.uploadPictureDiaposable = observable.subscribeOn(Schedulers.io()).observeOn(AndroidSchedulers.mainThread()).subscribe(new Consumer() { // from class: im.uwrkaxlmjj.ui.wallet.-$$Lambda$WalletWithdrawAddNewAccountActivity$8Jb9lY0rmygHa9IliZtHybzdmmY
            @Override // io.reactivex.functions.Consumer
            public final void accept(Object obj) throws Exception {
                this.f$0.lambda$toUploadPicture$6$WalletWithdrawAddNewAccountActivity(groupPosition, childPosition, (HuanHuiUploadFileResponseBean) obj);
            }
        }, new Consumer() { // from class: im.uwrkaxlmjj.ui.wallet.-$$Lambda$WalletWithdrawAddNewAccountActivity$AHdUebC6skkdB-wA4VJ7nJV1WgM
            @Override // io.reactivex.functions.Consumer
            public final void accept(Object obj) throws Exception {
                this.f$0.lambda$toUploadPicture$7$WalletWithdrawAddNewAccountActivity((Throwable) obj);
            }
        });
    }

    public /* synthetic */ void lambda$toUploadPicture$6$WalletWithdrawAddNewAccountActivity(int groupPosition, int childPosition, HuanHuiUploadFileResponseBean res) throws Exception {
        WalletWithdrawTemplateBean item;
        if (res != null) {
            if (res.isSuccess()) {
                Adapter adapter = this.adapter;
                if (adapter != null && (item = adapter.getItem(groupPosition)) != null) {
                    item.setPictureUrl(childPosition, res.furl);
                    toUploadPictures();
                    return;
                }
                return;
            }
            dismissCurrentDialog();
            ToastUtils.show((CharSequence) LocaleController.getString(R.string.UploadPhotoFailTips));
            FileLog.e(TAG, "toUploadPicture error :" + res.desc);
        }
    }

    public /* synthetic */ void lambda$toUploadPicture$7$WalletWithdrawAddNewAccountActivity(Throwable e) throws Exception {
        dismissCurrentDialog();
        ToastUtils.show((CharSequence) LocaleController.getString(R.string.UploadPhotoFailTips));
        FileLog.e(TAG, "toUploadPicture error", e);
    }

    private void addNewPaymentAccount() {
        List<WalletWithdrawTemplateBean> list = this.templateData;
        if (list == null || list.size() == 0 || TextUtils.isEmpty(this.templateId) || TextUtils.isEmpty(this.supportId) || this.isBinding) {
            return;
        }
        this.isBinding = true;
        TLRPCWallet.Builder builder = new TLRPCWallet.Builder();
        builder.setBusinessKey(Constants.KEY_BANK_CARD_BIND);
        builder.addParam("userId", Integer.valueOf(getUserConfig().getClientUserId()));
        builder.addParam("templateId", this.templateId);
        builder.addParam("supportId", this.supportId);
        WalletPaymentBankCardBean walletPaymentBankCardBean = this.paymentBankCardBean;
        if (walletPaymentBankCardBean != null) {
            builder.addParam(TtmlNode.ATTR_ID, Integer.valueOf(walletPaymentBankCardBean.id));
        }
        String infoJson = WalletWithdrawTemplateBean.createInfoJson(this.templateData);
        builder.addParam("info", infoJson);
        TLRPCWallet.TL_paymentTrans req = builder.build();
        getConnectionsManager().bindRequestToGuid(getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.wallet.-$$Lambda$WalletWithdrawAddNewAccountActivity$Lw8wN0Kvl4Mtu2M9O_AFF8I-ojY
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$addNewPaymentAccount$9$WalletWithdrawAddNewAccountActivity(tLObject, tL_error);
            }
        }), this.classGuid);
    }

    public /* synthetic */ void lambda$addNewPaymentAccount$9$WalletWithdrawAddNewAccountActivity(final TLObject response, final TLRPC.TL_error error) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.wallet.-$$Lambda$WalletWithdrawAddNewAccountActivity$qcSootlzxc8juYI-iSJMdnOzXpA
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$8$WalletWithdrawAddNewAccountActivity(error, response);
            }
        });
    }

    public /* synthetic */ void lambda$null$8$WalletWithdrawAddNewAccountActivity(TLRPC.TL_error error, TLObject response) {
        if (isFinishing()) {
            return;
        }
        this.isBinding = false;
        dismissCurrentDialog();
        if (error == null && (response instanceof TLRPCWallet.TL_paymentTransResult)) {
            TLApiModel2 model = (TLApiModel2) GsonUtils.fromJson(((TLRPCWallet.TL_paymentTransResult) response).getData(), TLApiModel2.class);
            if (model.isSuccess()) {
                getNotificationCenter().postNotificationName(NotificationCenter.bandCardNeedReload, new Object[0]);
                finishFragment();
                return;
            } else {
                ExceptionUtils.handlePayChannelException(model.result_desc);
                return;
            }
        }
        ExceptionUtils.handlePayChannelException(error.text);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void showSelectDictDialog(final int position, List<WalletWithdrawTemplateBean.DictItemBean> data) {
        if (data == null) {
            data = new ArrayList();
        }
        final WalletSelect1LineDialog<WalletWithdrawTemplateBean.DictItemBean> dialog = new WalletSelect1LineDialog<WalletWithdrawTemplateBean.DictItemBean>(getParentActivity()) { // from class: im.uwrkaxlmjj.ui.wallet.WalletWithdrawAddNewAccountActivity.2
            @Override // im.uwrkaxlmjj.ui.dialogs.WalletSelect1LineDialog, im.uwrkaxlmjj.ui.dialogs.WalletSelectAbsDialog
            public void onBindViewHolder(RecyclerListView.SelectionAdapter adapter, WalletSelect1LineDialog.Holder1Line holder, int position2, WalletWithdrawTemplateBean.DictItemBean item) {
                super.onBindViewHolder(adapter, holder, position2, item);
                holder.setGone((View) holder.ivIcon, true);
                holder.setGone((View) holder.ivSelect, true);
                holder.setText(holder.tvTitle, item.getDictLabel());
            }
        };
        dialog.getRecyclerViewContainerView().setRadiusAndShadow(AndroidUtilities.dp(12.0f), 3, 1, 1.0f);
        dialog.setRvAutoHideWhenEmptyData(false).setRecyclerViewMinHeight(AndroidUtilities.dp(250.0f));
        dialog.setShowConfirmButtonView(false).setOnItemClickListener(new OnItemClickListener() { // from class: im.uwrkaxlmjj.ui.wallet.-$$Lambda$WalletWithdrawAddNewAccountActivity$JS7259T4VDsp32CTJWqXq-eNyxU
            @Override // im.uwrkaxlmjj.ui.components.recyclerview.OnItemClickListener
            public final void onItemClick(View view, int i, Object obj) {
                this.f$0.lambda$showSelectDictDialog$10$WalletWithdrawAddNewAccountActivity(dialog, position, view, i, (WalletWithdrawTemplateBean.DictItemBean) obj);
            }
        }).setData(data);
        showDialog(dialog);
    }

    public /* synthetic */ void lambda$showSelectDictDialog$10$WalletWithdrawAddNewAccountActivity(WalletSelect1LineDialog dialog, int position, View view, int index, WalletWithdrawTemplateBean.DictItemBean item) {
        dialog.dismiss();
        Adapter adapter = this.adapter;
        if (adapter != null) {
            WalletWithdrawTemplateBean adapterItem = adapter.getItem(position);
            if (adapterItem != null) {
                adapterItem.setSelectIndex(index);
            }
            this.adapter.notifyItemChanged(position);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void showSelectPictureByPathDialog(final int groupPosition, final int childposition) {
        Adapter adapter;
        WalletWithdrawTemplateBean item;
        if (getParentActivity() == null || (adapter = this.adapter) == null || (item = adapter.getItem(groupPosition)) == null) {
            return;
        }
        boolean hasPic = item.getPictureArray() != null && item.hasPicturePathInIndex(childposition);
        BottomDialog dialog = new BottomDialog(getParentActivity());
        dialog.addDialogItem(new BottomDialog.NormalTextItem(0, LocaleController.getString("FromCamera", R.string.FromCamera), true));
        dialog.addDialogItem(new BottomDialog.NormalTextItem(1, LocaleController.getString("FromGallery", R.string.FromGallery), hasPic));
        if (hasPic) {
            BottomDialog.NormalTextItem delectItem = new BottomDialog.NormalTextItem(2, LocaleController.getString("Delete", R.string.Delete), false);
            delectItem.getContentTextView().setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteRedText));
            dialog.addDialogItem(delectItem);
        }
        dialog.setOnItemClickListener(new BottomDialog.OnItemClickListener() { // from class: im.uwrkaxlmjj.ui.wallet.-$$Lambda$WalletWithdrawAddNewAccountActivity$3KSSRACTQzhZoX2aUFEmkYmUi5c
            @Override // im.uwrkaxlmjj.ui.dialogs.BottomDialog.OnItemClickListener
            public final void onItemClick(int i, View view) {
                this.f$0.lambda$showSelectPictureByPathDialog$11$WalletWithdrawAddNewAccountActivity(groupPosition, childposition, i, view);
            }
        });
        showDialog(dialog);
    }

    public /* synthetic */ void lambda$showSelectPictureByPathDialog$11$WalletWithdrawAddNewAccountActivity(int groupPosition, int childposition, int id, View v) {
        Adapter adapter;
        WalletWithdrawTemplateBean adapterItem;
        dismissCurrentDialog();
        if (id != 2) {
            this.isSelectPicture = true;
            this.selectGroupPosition = groupPosition;
            this.selectChildPosition = childposition;
        }
        if (id == 0) {
            if (Build.VERSION.SDK_INT >= 23 && getParentActivity().checkSelfPermission("android.permission.CAMERA") != 0) {
                getParentActivity().requestPermissions(new String[]{"android.permission.CAMERA"}, 11);
                return;
            } else {
                openCamera();
                return;
            }
        }
        if (id == 1) {
            if (Build.VERSION.SDK_INT >= 23 && getParentActivity() != null && getParentActivity().checkSelfPermission(PermissionUtils.PERMISSION_READ_EXTERNAL_STORAGE) != 0) {
                getParentActivity().requestPermissions(new String[]{PermissionUtils.PERMISSION_READ_EXTERNAL_STORAGE}, 10);
                return;
            } else {
                toGallery();
                return;
            }
        }
        if (id == 2 && (adapter = this.adapter) != null && (adapterItem = adapter.getItem(groupPosition)) != null) {
            adapterItem.setPicturePath(childposition, null);
            this.adapter.notifyItemChanged(groupPosition);
        }
    }

    private void toGallery() {
        PhotoAlbumPickerActivity fragment = new PhotoAlbumPickerActivity(2, false, false, null);
        fragment.setMaxSelectedPhotos(1, true);
        fragment.setDelegate(new PhotoAlbumPickerActivity.PhotoAlbumPickerActivityDelegate() { // from class: im.uwrkaxlmjj.ui.wallet.WalletWithdrawAddNewAccountActivity.3
            @Override // im.uwrkaxlmjj.ui.PhotoAlbumPickerActivity.PhotoAlbumPickerActivityDelegate
            public void didSelectPhotos(ArrayList<SendMessagesHelper.SendingMediaInfo> photos, boolean notify, int scheduleDate, boolean blnOriginalImg) {
                if (WalletWithdrawAddNewAccountActivity.this.parentLayout != null && WalletWithdrawAddNewAccountActivity.this.parentLayout.fragmentsStack != null && WalletWithdrawAddNewAccountActivity.this.parentLayout.fragmentsStack.size() > 0) {
                    BaseFragment f = WalletWithdrawAddNewAccountActivity.this.parentLayout.fragmentsStack.get(WalletWithdrawAddNewAccountActivity.this.parentLayout.fragmentsStack.size() - 1);
                    if (f instanceof PhotoPickerActivity) {
                        f.finishFragment();
                    }
                }
                if (photos != null && photos.size() > 0) {
                    SendMessagesHelper.SendingMediaInfo info = photos.get(0);
                    if (info != null) {
                        WalletWithdrawAddNewAccountActivity walletWithdrawAddNewAccountActivity = WalletWithdrawAddNewAccountActivity.this;
                        walletWithdrawAddNewAccountActivity.showSelectPictureByPath(walletWithdrawAddNewAccountActivity.selectGroupPosition, WalletWithdrawAddNewAccountActivity.this.selectChildPosition, info.path);
                    }
                    WalletWithdrawAddNewAccountActivity.this.resetSelectPictureFlag();
                }
            }

            @Override // im.uwrkaxlmjj.ui.PhotoAlbumPickerActivity.PhotoAlbumPickerActivityDelegate
            public void startPhotoSelectActivity() {
                try {
                    Intent photoPickerIntent = new Intent("android.intent.action.GET_CONTENT");
                    photoPickerIntent.setType("image/*");
                    WalletWithdrawAddNewAccountActivity.this.startActivityForResult(photoPickerIntent, 14);
                } catch (Exception e) {
                    FileLog.e(e);
                }
            }
        });
        presentFragment(fragment);
    }

    public void openCamera() {
        if (getParentActivity() == null) {
            return;
        }
        try {
            Intent takePictureIntent = new Intent("android.media.action.IMAGE_CAPTURE");
            File image = AndroidUtilities.generatePicturePath();
            if (image != null) {
                if (Build.VERSION.SDK_INT >= 24) {
                    takePictureIntent.putExtra("output", FileProvider.getUriForFile(getParentActivity(), "singansfg.uwrkaxlmjj.sdancsuhsfj.provider", image));
                    takePictureIntent.addFlags(2);
                    takePictureIntent.addFlags(1);
                } else {
                    takePictureIntent.putExtra("output", Uri.fromFile(image));
                }
                this.currentPicturePath = image.getAbsolutePath();
            }
            startActivityForResult(takePictureIntent, 13);
        } catch (Exception e) {
            FileLog.e(e);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void showSelectPictureByPath(int selectGroupPosition, int selectChildPosition, String path) {
        Adapter adapter = this.adapter;
        if (adapter != null && selectGroupPosition >= 0 && selectChildPosition >= 0) {
            WalletWithdrawTemplateBean item = adapter.getItem(selectGroupPosition);
            if (item != null) {
                item.setPicturePath(selectChildPosition, path);
            }
            this.adapter.notifyItemChanged(selectGroupPosition);
            changeNextButtonEnable();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void resetSelectPictureFlag() {
        this.isSelectPicture = false;
        this.selectGroupPosition = -1;
        this.selectChildPosition = -1;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onActivityResultFragment(int requestCode, int resultCode, Intent data) {
        boolean isFromCamera;
        final String path;
        int orientation;
        if (resultCode == -1) {
            if (requestCode != 13 && requestCode != 14) {
                return;
            }
            if (requestCode != 13) {
                isFromCamera = false;
                path = AndroidUtilities.getPath(data.getData());
            } else {
                String path2 = this.currentPicturePath;
                isFromCamera = true;
                path = path2;
            }
            if (path == null) {
                return;
            }
            PhotoViewer.getInstance().setParentActivity(getParentActivity());
            int orientation2 = 0;
            try {
                ExifInterface ei = new ExifInterface(path);
                int exif = ei.getAttributeInt(ExifInterface.TAG_ORIENTATION, 1);
                if (exif == 3) {
                    orientation2 = JavaScreenCapturer.DEGREE_180;
                } else if (exif == 6) {
                    orientation2 = 90;
                } else if (exif == 8) {
                    orientation2 = JavaScreenCapturer.DEGREE_270;
                }
                orientation = orientation2;
            } catch (Exception e) {
                FileLog.e(e);
                orientation = 0;
            }
            ArrayList<Object> arrayList = new ArrayList<>();
            final int selectGroupIndex = this.selectGroupPosition;
            final int selectChildIndex = this.selectChildPosition;
            int selectChildIndex2 = orientation;
            arrayList.add(new MediaController.PhotoEntry(0, 0, 0L, path, selectChildIndex2, false));
            PhotoViewer.getInstance().setIsFcCrop(false);
            PhotoViewer.getInstance().setMaxSelectedPhotos(1, true);
            PhotoViewer.getInstance().openPhotoForSelect(arrayList, 0, 3, new PhotoViewer.EmptyPhotoViewerProvider() { // from class: im.uwrkaxlmjj.ui.wallet.WalletWithdrawAddNewAccountActivity.4
                @Override // im.uwrkaxlmjj.ui.PhotoViewer.EmptyPhotoViewerProvider, im.uwrkaxlmjj.ui.PhotoViewer.PhotoViewerProvider
                public void sendButtonPressed(int index, VideoEditedInfo videoEditedInfo, boolean notify, int scheduleDate) {
                    WalletWithdrawAddNewAccountActivity.this.showSelectPictureByPath(selectGroupIndex, selectChildIndex, path);
                }

                @Override // im.uwrkaxlmjj.ui.PhotoViewer.EmptyPhotoViewerProvider, im.uwrkaxlmjj.ui.PhotoViewer.PhotoViewerProvider
                public boolean allowCaption() {
                    return false;
                }

                @Override // im.uwrkaxlmjj.ui.PhotoViewer.EmptyPhotoViewerProvider, im.uwrkaxlmjj.ui.PhotoViewer.PhotoViewerProvider
                public boolean canScrollAway() {
                    return false;
                }

                @Override // im.uwrkaxlmjj.ui.PhotoViewer.EmptyPhotoViewerProvider, im.uwrkaxlmjj.ui.PhotoViewer.PhotoViewerProvider
                public boolean canCaptureMorePhotos() {
                    return false;
                }
            }, null);
            if (isFromCamera) {
                AndroidUtilities.addMediaToGallery(path);
                this.currentPicturePath = null;
            }
        }
        resetSelectPictureFlag();
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onRequestPermissionsResultFragment(int requestCode, String[] permissions, int[] grantResults) {
        super.onRequestPermissionsResultFragment(requestCode, permissions, grantResults);
        if (requestCode == 10) {
            boolean tag = true;
            int length = grantResults.length;
            for (int i = 0; i < length; i++) {
                int a = grantResults[i];
                tag = a == 0;
                if (!tag) {
                    break;
                }
            }
            if (tag && this.isSelectPicture) {
                toGallery();
                return;
            } else {
                resetSelectPictureFlag();
                return;
            }
        }
        if (requestCode == 11) {
            if (grantResults != null && grantResults[0] == 0) {
                openCamera();
            } else {
                resetSelectPictureFlag();
            }
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    protected void onTransitionAnimationEnd(boolean isOpen, boolean backward) {
        super.onTransitionAnimationEnd(isOpen, backward);
        if (isOpen && !backward) {
            getTemplateData();
        }
    }

    private String guessMimeType(String path) {
        FileNameMap fileNameMap = URLConnection.getFileNameMap();
        String contentTypeFor = null;
        try {
            contentTypeFor = fileNameMap.getContentTypeFor(URLEncoder.encode(path, "UTF-8"));
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        if (contentTypeFor == null) {
            return "application/octet-stream";
        }
        return contentTypeFor;
    }

    private void cancelUploadPicture() {
        Disposable disposable = this.uploadPictureDiaposable;
        if (disposable != null && !disposable.isDisposed()) {
            this.uploadPictureDiaposable.dispose();
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onFragmentDestroy() {
        cancelUploadPicture();
        RecyclerListView recyclerListView = this.rv;
        if (recyclerListView != null) {
            recyclerListView.setLayoutManager(null);
            this.rv.setAdapter(null);
        }
        super.onFragmentDestroy();
        this.doneMenu = null;
        this.rv = null;
        Adapter adapter = this.adapter;
        if (adapter != null) {
            adapter.destroy();
            this.adapter = null;
        }
        this.paymentBankCardBean = null;
        List<WalletWithdrawTemplateBean> list = this.templateData;
        if (list != null) {
            list.clear();
            this.templateData = null;
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    class Adapter extends RecyclerListView.SelectionAdapter {
        static final int VIEW_TYPE_INPUT_TEXT = 0;
        static final int VIEW_TYPE_PICTURE = 2;
        static final int VIEW_TYPE_SELECT = 1;
        private SparseArray<WatcherWrapper> watcherSparseArray = new SparseArray<>();
        private SparseArray<PictureAdapter> pictureAdapterSparseArray = new SparseArray<>();

        public Adapter() {
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SelectionAdapter
        public boolean isEnabled(RecyclerView.ViewHolder holder) {
            return false;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public RecyclerView.ViewHolder onCreateViewHolder(ViewGroup parent, int viewType) {
            View view;
            if (viewType == 0) {
                view = LayoutInflater.from(WalletWithdrawAddNewAccountActivity.this.getParentActivity()).inflate(R.layout.wallet_item_withdraw_add_way_type_input, parent, false);
            } else if (viewType == 1) {
                view = LayoutInflater.from(WalletWithdrawAddNewAccountActivity.this.getParentActivity()).inflate(R.layout.wallet_item_withdraw_add_way_type_select, parent, false);
            } else if (viewType == 2) {
                View view2 = LayoutInflater.from(WalletWithdrawAddNewAccountActivity.this.getParentActivity()).inflate(R.layout.wallet_item_withdraw_add_way_type_picture, parent, false);
                RecyclerListView rv = (RecyclerListView) view2.findViewById(R.attr.rv);
                if (rv != null) {
                    rv.setLayoutManager(new GridLayoutManager(parent.getContext(), 2));
                    rv.addItemDecoration(new DefaultItemDecoration().setDividerColor(0).setDividerWidth(AndroidUtilities.dp(16.0f)).setDividerHeight(AndroidUtilities.dp(16.0f)));
                }
                view = view2;
            } else {
                throw new IllegalArgumentException("Unsupport withdraw template type");
            }
            return new PageHolder(view, 0);
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void onBindViewHolder(RecyclerView.ViewHolder holder1, final int position) {
            RecyclerListView rv;
            PageHolder holder = (PageHolder) holder1;
            final WalletWithdrawTemplateBean item = getItem(position);
            if (item == null) {
                return;
            }
            int viewType = holder.getItemViewType();
            MryTextView tvTitle = (MryTextView) holder.itemView.findViewById(R.attr.tvTitle);
            holder.setText(tvTitle, item.getDisplayName());
            if (viewType == 0) {
                final MryEditText et = (MryEditText) holder.itemView.findViewById(R.attr.et);
                ConstraintLayout container = (ConstraintLayout) holder.itemView.findViewById(R.attr.container);
                holder.setOnClickListener(container, new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.wallet.-$$Lambda$WalletWithdrawAddNewAccountActivity$Adapter$51BCGBMIrwj03gjrlHa4Hb2wYy0
                    @Override // android.view.View.OnClickListener
                    public final void onClick(View view) {
                        this.f$0.lambda$onBindViewHolder$0$WalletWithdrawAddNewAccountActivity$Adapter(et, view);
                    }
                });
                if (item.getTextInput() == null) {
                    holder.setHint(et, item.getExplan());
                } else {
                    holder.setText(et, item.getTextInput());
                }
                if (et != null) {
                    WatcherWrapper watcherWrapper = this.watcherSparseArray.get(position);
                    if (watcherWrapper == null) {
                        WatcherWrapper watcherWrapper2 = new WatcherWrapper(et, new TextWatcher() { // from class: im.uwrkaxlmjj.ui.wallet.WalletWithdrawAddNewAccountActivity.Adapter.2
                            @Override // android.text.TextWatcher
                            public void beforeTextChanged(CharSequence s, int start, int count, int after) {
                            }

                            @Override // android.text.TextWatcher
                            public void onTextChanged(CharSequence s, int start, int before, int count) {
                            }

                            @Override // android.text.TextWatcher
                            public void afterTextChanged(Editable s) {
                                if (s == null) {
                                    return;
                                }
                                item.setTextInput(s.toString());
                                WalletWithdrawAddNewAccountActivity.this.changeNextButtonEnable();
                            }
                        });
                        this.watcherSparseArray.put(position, watcherWrapper2);
                        return;
                    }
                    return;
                }
                return;
            }
            if (1 == viewType) {
                MryTextView tvContent = (MryTextView) holder.itemView.findViewById(R.attr.tvContent);
                ConstraintLayout container2 = (ConstraintLayout) holder.itemView.findViewById(R.attr.container);
                holder.setOnClickListener(container2, new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.wallet.-$$Lambda$WalletWithdrawAddNewAccountActivity$Adapter$JTcbbDx71KdsAlAK6JTUGqyVf9A
                    @Override // android.view.View.OnClickListener
                    public final void onClick(View view) {
                        this.f$0.lambda$onBindViewHolder$1$WalletWithdrawAddNewAccountActivity$Adapter(position, item, view);
                    }
                });
                if (item.getSelectDictItem() == null) {
                    holder.setHint(tvContent, item.getExplan());
                } else {
                    holder.setText(tvContent, item.getSelectDictItem().getDictLabel());
                }
                if (tvContent != null) {
                    WatcherWrapper watcherWrapper3 = this.watcherSparseArray.get(position);
                    if (watcherWrapper3 == null) {
                        WatcherWrapper watcherWrapper4 = new WatcherWrapper(tvContent, new TextWatcher() { // from class: im.uwrkaxlmjj.ui.wallet.WalletWithdrawAddNewAccountActivity.Adapter.3
                            @Override // android.text.TextWatcher
                            public void beforeTextChanged(CharSequence s, int start, int count, int after) {
                            }

                            @Override // android.text.TextWatcher
                            public void onTextChanged(CharSequence s, int start, int before, int count) {
                            }

                            @Override // android.text.TextWatcher
                            public void afterTextChanged(Editable s) {
                                if (s == null) {
                                    return;
                                }
                                item.setTextInput(s.toString());
                                WalletWithdrawAddNewAccountActivity.this.changeNextButtonEnable();
                            }
                        });
                        this.watcherSparseArray.put(position, watcherWrapper4);
                        return;
                    }
                    return;
                }
                return;
            }
            if (2 == viewType && (rv = (RecyclerListView) holder.itemView.findViewById(R.attr.rv)) != null && !rv.isComputingLayout()) {
                rv.setOnItemClickListener(new RecyclerListView.OnItemClickListener() { // from class: im.uwrkaxlmjj.ui.wallet.-$$Lambda$WalletWithdrawAddNewAccountActivity$Adapter$_0LAGA1YHP6dtYyo49tEUKjCWB4
                    @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.OnItemClickListener
                    public final void onItemClick(View view, int i) {
                        this.f$0.lambda$onBindViewHolder$2$WalletWithdrawAddNewAccountActivity$Adapter(position, view, i);
                    }
                });
                PictureAdapter adapter = this.pictureAdapterSparseArray.get(position);
                if (adapter == null) {
                    PictureAdapter adapter2 = new PictureAdapter(item.getPictureCount(), WalletWithdrawAddNewAccountActivity.this.paymentBankCardBean == null);
                    adapter2.data = item.getPictureArray();
                    rv.setAdapter(adapter2);
                    this.pictureAdapterSparseArray.put(position, adapter2);
                    return;
                }
                adapter.data = item.getPictureArray();
                adapter.notifyDataSetChanged();
            }
        }

        public /* synthetic */ void lambda$onBindViewHolder$0$WalletWithdrawAddNewAccountActivity$Adapter(final MryEditText et, View v) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.wallet.WalletWithdrawAddNewAccountActivity.Adapter.1
                @Override // java.lang.Runnable
                public void run() {
                    et.setFocusable(true);
                    et.setFocusableInTouchMode(true);
                    et.requestFocus();
                    AndroidUtilities.showKeyboard(et);
                }
            });
        }

        public /* synthetic */ void lambda$onBindViewHolder$1$WalletWithdrawAddNewAccountActivity$Adapter(int position, WalletWithdrawTemplateBean item, View v) {
            WalletWithdrawAddNewAccountActivity.this.showSelectDictDialog(position, item.getDictList());
        }

        public /* synthetic */ void lambda$onBindViewHolder$2$WalletWithdrawAddNewAccountActivity$Adapter(int position, View view, int childPosition) {
            WalletWithdrawAddNewAccountActivity.this.showSelectPictureByPathDialog(position, childPosition);
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void onViewAttachedToWindow(RecyclerView.ViewHolder holder) {
            WatcherWrapper watcherWrapper;
            super.onViewAttachedToWindow(holder);
            if (holder.getItemViewType() == 0 && (watcherWrapper = this.watcherSparseArray.get(holder.getAdapterPosition())) != null) {
                watcherWrapper.onResume();
            }
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void onViewDetachedFromWindow(RecyclerView.ViewHolder holder) {
            WatcherWrapper watcherWrapper;
            super.onViewDetachedFromWindow(holder);
            if (holder.getItemViewType() == 0 && (watcherWrapper = this.watcherSparseArray.get(holder.getAdapterPosition())) != null) {
                watcherWrapper.onPasue();
            }
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemViewType(int position) {
            WalletWithdrawTemplateBean item = getItem(position);
            if (item == null || item.isTypeInputText()) {
                return 0;
            }
            if (item.isTypeSelect()) {
                return 1;
            }
            if (!item.isTypePicture()) {
                return 0;
            }
            return 2;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemCount() {
            if (WalletWithdrawAddNewAccountActivity.this.templateData != null) {
                return WalletWithdrawAddNewAccountActivity.this.templateData.size();
            }
            return 0;
        }

        WalletWithdrawTemplateBean getItem(int position) {
            if (WalletWithdrawAddNewAccountActivity.this.templateData != null && position >= 0 && position < WalletWithdrawAddNewAccountActivity.this.templateData.size()) {
                return (WalletWithdrawTemplateBean) WalletWithdrawAddNewAccountActivity.this.templateData.get(position);
            }
            return null;
        }

        void destroy() {
            SparseArray<WatcherWrapper> sparseArray = this.watcherSparseArray;
            if (sparseArray != null) {
                sparseArray.clear();
                this.watcherSparseArray = null;
            }
            SparseArray<PictureAdapter> sparseArray2 = this.pictureAdapterSparseArray;
            if (sparseArray2 != null) {
                sparseArray2.clear();
                this.pictureAdapterSparseArray = null;
            }
        }
    }

    public static class PictureAdapter extends RecyclerListView.SelectionAdapter {
        int count;
        WalletWithdrawTemplateBean.PictureBean[] data;
        boolean isAddNewAccount;

        public PictureAdapter(int count, boolean isAddNewAccount) {
            this.count = count;
            this.data = new WalletWithdrawTemplateBean.PictureBean[count];
            this.isAddNewAccount = isAddNewAccount;
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SelectionAdapter
        public boolean isEnabled(RecyclerView.ViewHolder holder) {
            return true;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public RecyclerView.ViewHolder onCreateViewHolder(ViewGroup parent, int viewType) {
            return new PageHolder(LayoutInflater.from(parent.getContext()).inflate(R.layout.wallet_item_withdraw_add_way_type_picture_item, parent, false), ColorUtils.getColor(R.color.window_background_gray));
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void onBindViewHolder(RecyclerView.ViewHolder holder, int position) {
            ImageView iv = (ImageView) holder.itemView.findViewById(R.attr.iv);
            if (iv != null) {
                WalletWithdrawTemplateBean.PictureBean item = getItem(position);
                if (item != null) {
                    if (this.isAddNewAccount) {
                        if (!TextUtils.isEmpty(item.getUrl())) {
                            GlideUtil.loadUrl(iv, item.getUrl(), 0, 0);
                            return;
                        } else {
                            GlideUtil.loadUrl(iv, item.getPath(), 0, 0);
                            return;
                        }
                    }
                    if (!TextUtils.isEmpty(item.getPath())) {
                        GlideUtil.loadUrl(iv, item.getPath(), 0, 0);
                        return;
                    } else {
                        GlideUtil.loadUrl(iv, item.getOriginUrl(), 0, 0);
                        return;
                    }
                }
                iv.setImageResource(0);
            }
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemCount() {
            return this.count;
        }

        WalletWithdrawTemplateBean.PictureBean getItem(int position) {
            WalletWithdrawTemplateBean.PictureBean[] pictureBeanArr = this.data;
            if (pictureBeanArr != null && position >= 0 && position < pictureBeanArr.length) {
                return pictureBeanArr[position];
            }
            return null;
        }
    }

    private static class WatcherWrapper {
        private boolean isWatched;
        WeakReference<TextView> tvW;
        TextWatcher watcher;

        public WatcherWrapper(TextView tv, TextWatcher watcher) {
            this.tvW = new WeakReference<>(tv);
            this.watcher = watcher;
            onResume();
        }

        void onResume() {
            TextWatcher textWatcher;
            TextView tv = this.tvW.get();
            if (tv != null && (textWatcher = this.watcher) != null && !this.isWatched) {
                this.isWatched = true;
                tv.addTextChangedListener(textWatcher);
            }
        }

        void onPasue() {
            TextWatcher textWatcher;
            TextView tv = this.tvW.get();
            if (tv != null && (textWatcher = this.watcher) != null) {
                tv.removeTextChangedListener(textWatcher);
            }
            this.isWatched = false;
        }
    }
}
