<?php

namespace app\controllers;


class TestController extends \yii\web\Controller
{
	public function actionTest($name){
		#&name = Yii::$app->request->get('unserialize');

		return unserialize(base64_decode($name));
	}
}