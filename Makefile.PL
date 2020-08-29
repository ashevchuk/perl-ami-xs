use ExtUtils::MakeMaker;
use EV::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(EV::MakeMaker::ev_args (
    NAME              => 'AMI',
    VERSION_FROM      => 'lib/AMI.pm', # finds $VERSION
    CONFIGURE_REQUIRES => {
        'EV' => 4.33,
    },
    PREREQ_PM         => {
        'EV' => 4.33,
    },
    ($] >= 5.005 ?     ## Add these new keywords supported since 5.005
      (ABSTRACT_FROM  => 'lib/AMI.pm', # retrieve abstract from module
       AUTHOR         => 'root <root@localdomain>') : ()),
    LIBS              => ['-lpthread'], # e.g., '-lm'
    DEFINE            => '-DDEBUG', # e.g., '-DHAVE_SOMETHING'
    INC               => '-I.', # e.g., '-I. -I/usr/include/other'
    OBJECT            => '$(O_FILES)', # link all the C files too
#    CCFLAGS           => '-std=gnu99 -pthread -msse2 -mavx -foptimize-strlen -finline-functions -finline-small-functions -findirect-inlining -finline-functions-called-once -fearly-inlining -fno-gcse -faggressive-loop-optimizations -fexpensive-optimizations -free -fira-algorithm=CB -fira-region=mixed -fira-hoist-pressure -fira-loop-pressure -fschedule-insns -fsched-pressure -fsched-spec-load -fsched2-use-superblocks -fipa-pta -fipa-icf -ffinite-loops -ftree-ch -floop-parallelize-all -fgraphite-identity -floop-nest-optimize -ftree-loop-if-convert -ftree-loop-distribution -floop-interchange -ftree-parallelize-loops=32 -ftree-vectorize -fsplit-paths -fpartial-inlining -fpredictive-commoning -freorder-blocks -freorder-blocks-algorithm=stc -freorder-blocks-and-partition -fstrict-aliasing -fweb -funroll-loops -flto -ffast-math -fschedule-fusion',
     CCFLAGS           => '-std=gnu99 -g',
));
