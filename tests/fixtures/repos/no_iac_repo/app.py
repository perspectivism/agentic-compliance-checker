# Fixture: no_iac_repo
# A plain application with no IaC, no CI, no Dockerfile. Most infrastructure
# controls (encryption, IAM, network) should resolve to `not_assessable` here —
# this is the graceful-degradation case, not a pile of false "gap" verdicts.


def add(a: int, b: int) -> int:
    return a + b


def main() -> None:
    print(add(2, 3))


if __name__ == "__main__":
    main()
