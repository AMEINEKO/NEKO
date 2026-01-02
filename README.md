# NEKO
NEKO is a transport protocol implementation derived from the Meta branch of mihomo (GPL-3.0).
所有代码均使用 AI 生成。

**A quiet, resilient encrypted transport for real-world networks.**  
**一个安静、克制、面向真实网络环境的加密传输协议。**

---

## What is NEKO

**NEKO** is a structured encrypted transport designed to operate quietly and persistently under real-world network constraints.

It does not aim to imitate existing protocols, nor does it attempt to confront censorship directly.  
Instead, NEKO focuses on reducing unnecessary exposure, avoiding distinctive behavior, and remaining stable over long periods of time.

**NEKO 是一个结构化的加密传输协议，  
它的目标不是伪装、不是对抗，而是在现实网络环境中安静地存在并持续工作。**

---

## Design Philosophy / 设计理念

**Quiet rather than loud**  
**Resilient rather than aggressive**  
**Practical rather than symbolic**

NEKO avoids unnecessary noise, exaggerated randomness, and highly recognizable behaviors.  
It prioritizes stability, adaptability, and long-term survivability over short-term evasion tricks.

**NEKO 选择克制而非张扬，  
选择适应而非对抗，  
选择长期可用而非短期效果。**

---

## Why the name NEKO / 为什么叫 NEKO

### 中文

NEKO（猫）并不是一个情绪化的名字。  
它代表了一种生存方式。

猫不会正面冲撞危险，也不会主动吸引注意。  
它通过安静、灵活和对环境的适应，选择活下去。

这个项目诞生于一段特殊的时代背景。  
在中国新冠疫情期间的过度防控中，我的爷爷与许多普通人一样，安静地离开了这个世界，没有留下应有的记录。

NEKO 不是愤怒的产物，  
而是一次纪念。

这是我选择用工程的方式，  
为抗审查社区添一块小小的砖，  
也是为那些被安静带走的人保留一份记忆。

---

### English

The name **NEKO** (猫, "cat") is not emotional.  
It represents a way of survival.

A cat does not confront danger head-on, nor does it seek attention.  
It survives through quiet adaptation and awareness of its surroundings.

This project was created during a difficult period.  
My grandfather passed away during the time of excessive COVID-19 control in China, as did many ordinary people whose lives ended quietly and without recognition.

NEKO is not built from anger.  
It is built as an act of remembrance.

This project is my small contribution to the anti-censorship community,  
and a way to preserve memory through engineering rather than slogans.

---

## Technical Characteristics

- Structured framing with explicit boundaries  
- Encrypted payload with masked layout elements  
- Minimal and constrained randomness  
- Probe-safe failure behavior (silence rather than response)  
- Designed for both TCP and UDP transport

NEKO intentionally avoids complex behavior scripting, heavy noise injection, or protocol impersonation.

---

## When to use NEKO

**NEKO is suitable for:**
- Personal or small-scale use
- Long-lived connections in restrictive environments
- Scenarios where stability and low visibility matter

**NEKO is not designed for:**
- Large public services
- High-profile or high-exposure deployments
- Situations requiring protocol impersonation (e.g. TLS camouflage)

---

## Project Status

NEKO is under active development.  
The protocol and implementation may evolve, but the design philosophy will remain consistent.

Backward compatibility is not guaranteed across major versions.

---

## In Memory

This project is dedicated to those who were lost quietly.  
May they not be forgotten.

---

## Credits

- Based on the Meta branch of MetaCubeX/mihomo (https://github.com/MetaCubeX/mihomo/tree/Meta)

## License

GPL-3.0-or-later. See `LICENSE`.
