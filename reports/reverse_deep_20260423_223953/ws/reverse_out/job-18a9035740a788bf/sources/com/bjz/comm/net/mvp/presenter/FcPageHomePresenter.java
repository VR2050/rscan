package com.bjz.comm.net.mvp.presenter;

import com.bjz.comm.net.base.DataListener;
import com.bjz.comm.net.bean.BResponse;
import com.bjz.comm.net.bean.RespFcListBean;
import com.bjz.comm.net.mvp.contract.BaseFcContract;
import com.bjz.comm.net.mvp.model.FcPageHomeModel;
import com.bjz.comm.net.utils.RxHelper;
import java.util.ArrayList;

/* JADX INFO: loaded from: classes4.dex */
public class FcPageHomePresenter implements BaseFcContract.IFcPageHomePresenter {
    BaseFcContract.IFcPageHomeView mView;
    private FcPageHomeModel model;

    public FcPageHomePresenter(BaseFcContract.IFcPageHomeView view) {
        this.model = null;
        this.mView = view;
        if (0 == 0) {
            this.model = new FcPageHomeModel();
        }
    }

    @Override // com.bjz.comm.net.mvp.contract.BaseFcContract.IFcPageHomePresenter
    public void getFcList(int limit, long forumID) {
        this.model.getFcList(limit, forumID, new DataListener<BResponse<ArrayList<RespFcListBean>>>() { // from class: com.bjz.comm.net.mvp.presenter.FcPageHomePresenter.1
            @Override // com.bjz.comm.net.base.DataListener
            public void onResponse(BResponse<ArrayList<RespFcListBean>> result) {
                if (result != null) {
                    if (result.isState()) {
                        FcPageHomePresenter.this.mView.getFcListSucc(result.Data == null ? new ArrayList<>() : result.Data);
                        return;
                    } else {
                        FcPageHomePresenter.this.mView.getFcListFailed(result.Message);
                        return;
                    }
                }
                FcPageHomePresenter.this.mView.getFcListFailed(null);
            }

            @Override // com.bjz.comm.net.base.DataListener
            public void onError(Throwable throwable) {
                FcPageHomePresenter.this.mView.getFcListFailed(RxHelper.getInstance().getErrorInfo(throwable));
            }
        });
    }

    @Override // com.bjz.comm.net.base.IBPresenter
    public void unSubscribeTask() {
        this.model.unSubscribeTask();
    }
}
