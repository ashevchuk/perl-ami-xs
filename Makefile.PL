use ExtUtils::MakeMaker;
use EV::MakeMaker;

WriteMakefile(EV::MakeMaker::ev_args (
    NAME              => 'AMI',
    VERSION_FROM      => 'lib/AMI.pm',
    CONFIGURE_REQUIRES => {
        'EV' => 4.33,
    },
    PREREQ_PM         => {
        'EV' => 4.33,
    },
    ABSTRACT_FROM  => 'lib/AMI.pm',
    AUTHOR         => 'user <user@localdomain>',
    LIBS              => ['-lpthread'],
    DEFINE            => '-DDEBUG',
    INC               => '-I.',
    OBJECT            => '$(O_FILES)',
#    CCFLAGS           => '-std=gnu99 -pthread -msse2 -mavx -foptimize-strlen -finline-functions -finline-small-functions -findirect-inlining -finline-functions-called-once -fearly-inlining -fno-gcse -faggressive-loop-optimizations -fexpensive-optimizations -free -fira-algorithm=CB -fira-region=mixed -fira-hoist-pressure -fira-loop-pressure -fschedule-insns -fsched-pressure -fsched-spec-load -fsched2-use-superblocks -fipa-pta -fipa-icf -ffinite-loops -ftree-ch -floop-parallelize-all -fgraphite-identity -floop-nest-optimize -ftree-loop-if-convert -ftree-loop-distribution -floop-interchange -ftree-parallelize-loops=32 -ftree-vectorize -fsplit-paths -fpartial-inlining -fpredictive-commoning -freorder-blocks -freorder-blocks-algorithm=stc -freorder-blocks-and-partition -fstrict-aliasing -fweb -funroll-loops -flto -ffast-math -fschedule-fusion',
     CCFLAGS           => '-std=gnu99',
));
