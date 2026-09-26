// Apex Captcha - 行为验证前端逻辑
(function() {
  // 行为信号采集
  const signals = {
    mouseMoves: 0,
    touches: 0,
    keypresses: 0,
    scrolls: 0,
    startTime: Date.now(),
  };

  document.addEventListener('mousemove', () => { signals.mouseMoves++; }, { passive: true });
  document.addEventListener('touchmove', () => { signals.touches++; }, { passive: true });
  document.addEventListener('keydown', () => { signals.keypresses++; }, { passive: true });
  document.addEventListener('scroll', () => { signals.scrolls++; }, { passive: true });

  function getFingerprint() {
    return {
      webdriver: !!navigator.webdriver,
      languages: navigator.languages || [],
      platform: navigator.platform || '',
      hardwareConcurrency: navigator.hardwareConcurrency || 0,
      deviceMemory: navigator.deviceMemory || 0,
      screenWidth: screen.width,
      screenHeight: screen.height,
    };
  }

  window.startCaptcha = async function(box) {
    if (box.dataset.status === 'success' || box.dataset.status === 'verifying') return;

    box.dataset.status = 'verifying';
    box.classList.add('verifying');
    const percent = box.querySelector('.apex-captcha-percent');
    if (percent) percent.textContent = '0%';

    let progress = 0;
    const progressInterval = setInterval(() => {
      progress = Math.min(progress + Math.random() * 15 + 5, 90);
      if (percent) percent.textContent = Math.floor(progress) + '%';
    }, 100);

    try {
      // Step 1: 获取挑战
      const challengeRes = await window.apiClient.post('/api/captcha/challenge', {});
      if (!challengeRes.success) throw new Error(challengeRes.message || '无法获取验证挑战');

      // Step 2: 汇总信号
      const payload = {
        ...getFingerprint(),
        mouseMoves: signals.mouseMoves,
        touches: signals.touches,
        keypresses: signals.keypresses,
        scrolls: signals.scrolls,
        dwellTime: Date.now() - signals.startTime,
      };

      // Step 3: 提交验证
      const verifyRes = await window.apiClient.post('/api/captcha/verify', {
        signals: payload,
        challenge: challengeRes.challenge,
        signature: challengeRes.signature,
      });

      clearInterval(progressInterval);

      if (verifyRes.success) {
        if (percent) percent.textContent = '100%';
        setTimeout(() => {
          box.dataset.token = verifyRes.token;
          window.__captchaToken = verifyRes.token;
          box.dataset.status = 'success';
          box.classList.remove('verifying');
          box.classList.add('success');
          if (percent) percent.textContent = '验证成功';
        }, 200);
      } else {
        if (percent) percent.textContent = '验证失败';
        setTimeout(() => {
          box.dataset.status = 'idle';
          box.classList.remove('verifying');
          if (percent) percent.textContent = '0%';
        }, 1500);
      }
    } catch (err) {
      clearInterval(progressInterval);
      if (percent) percent.textContent = '网络错误';
      setTimeout(() => {
        box.dataset.status = 'idle';
        box.classList.remove('verifying');
        if (percent) percent.textContent = '0%';
      }, 1500);
    }
  };

  console.log('[Apex] Captcha 模块已加载');
})();
