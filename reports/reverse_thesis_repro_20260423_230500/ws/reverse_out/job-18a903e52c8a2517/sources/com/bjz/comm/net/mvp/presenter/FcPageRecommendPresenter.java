package com.bjz.comm.net.mvp.presenter;

import com.bjz.comm.net.base.DataListener;
import com.bjz.comm.net.bean.BResponse;
import com.bjz.comm.net.bean.RespFcListBean;
import com.bjz.comm.net.mvp.contract.BaseFcContract;
import com.bjz.comm.net.mvp.model.FcPageRecommendModel;
import com.bjz.comm.net.utils.RxHelper;
import java.util.ArrayList;

/* JADX INFO: loaded from: classes4.dex */
public class FcPageRecommendPresenter implements BaseFcContract.IFcPageRecommendPresenter {
    BaseFcContract.IFcPageRecommendView mView;
    private FcPageRecommendModel model;

    public FcPageRecommendPresenter(BaseFcContract.IFcPageRecommendView view) {
        this.model = null;
        this.mView = view;
        if (0 == 0) {
            this.model = new FcPageRecommendModel();
        }
    }

    @Override // com.bjz.comm.net.mvp.contract.BaseFcContract.IFcPageRecommendPresenter
    public void getFcList(int limit, long forumID) {
        this.model.getFcList(limit, forumID, new DataListener<BResponse<ArrayList<RespFcListBean>>>() { // from class: com.bjz.comm.net.mvp.presenter.FcPageRecommendPresenter.1
            @Override // com.bjz.comm.net.base.DataListener
            public void onResponse(BResponse<ArrayList<RespFcListBean>> result) {
                if (result != null) {
                    if (result.isState()) {
                        FcPageRecommendPresenter.this.mView.getFcListSucc(result.Data == null ? new ArrayList<>() : result.Data);
                        return;
                    } else {
                        FcPageRecommendPresenter.this.mView.getFcListFailed(result.Message);
                        return;
                    }
                }
                FcPageRecommendPresenter.this.mView.getFcListFailed(null);
            }

            @Override // com.bjz.comm.net.base.DataListener
            public void onError(Throwable throwable) {
                FcPageRecommendPresenter.this.mView.getFcListFailed(RxHelper.getInstance().getErrorInfo(throwable));
            }
        });
    }

    @Override // com.bjz.comm.net.base.IBPresenter
    public void unSubscribeTask() {
        this.model.unSubscribeTask();
    }
}
